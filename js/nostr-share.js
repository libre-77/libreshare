// Nostr gift-wrap delivery (ARCHITECTURE.md §6). A share link is the actual key,
// so it must never travel a plaintext channel (email/SMS/chat) where the channel
// operator logs it. Instead the link is sealed into a NIP-59 gift wrap addressed
// to one recipient and published to their inbox relay.
//
// Three nested layers, all built by nostr-tools nip44/nip59 — no crypto is
// hand-rolled here (§11):
//   rumor    kind:1063  content = link            unsigned  → deniability
//   seal     kind:13    NIP-44(sender→recipient)  signed by sender
//   giftwrap kind:1059  NIP-44(ephemeral→recip)   signed by a throwaway key,
//                       timestamp randomized ±2 days
// A relay sees only kind:1059 from a random pubkey at a random time with a `p`
// tag. It learns neither the content nor the real sender. The unsigned rumor
// means a recipient who leaks it cannot cryptographically prove who sent it.
//
// The pure functions (wrapLink/unwrapToLink/key parsing) touch no network and
// import cleanly in Node for tests. Relay I/O (publishWrap/fetchWraps) needs a
// WebSocket global, so it only runs in the browser.

import { generateSecretKey, getPublicKey, nip19, nip59 } from '../vendor/nostr-tools.js';

const KIND_FILE_RUMOR = 1063; // NIP-94-style file metadata; carries the link
const KIND_GIFT_WRAP = 1059;
const APP_TAG = 'ls';

const HEX64 = /^[0-9a-f]{64}$/i;

// --- key parsing / identity -------------------------------------------------

// Accept an npub bech32 or a raw 64-hex pubkey; return hex.
export function parsePubkey(input) {
  const s = (input || '').trim();
  if (HEX64.test(s)) return s.toLowerCase();
  const d = nip19.decode(s);
  if (d.type !== 'npub') throw new Error('expected an npub (recipient public key)');
  return d.data;
}

// Accept an nsec bech32, a raw 64-hex secret, or already-decoded key bytes;
// return the secret key bytes.
export function parseSecretKey(input) {
  if (input instanceof Uint8Array) {
    if (input.length !== 32) throw new Error('secret key must be 32 bytes');
    return input;
  }
  const s = (input || '').trim();
  if (HEX64.test(s)) {
    const out = new Uint8Array(32);
    for (let i = 0; i < 32; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
    return out;
  }
  const d = nip19.decode(s);
  if (d.type !== 'nsec') throw new Error('expected an nsec (your secret key)');
  return d.data;
}

// A fresh Nostr identity for someone who does not have one. The nsec is a
// secret — treat it like a password; the npub is what you hand out to receive.
export function generateIdentity() {
  const sk = generateSecretKey();
  const pk = getPublicKey(sk);
  return { nsec: nip19.nsecEncode(sk), npub: nip19.npubEncode(pk), pubkeyHex: pk };
}

export function npubOf(secret) {
  const sk = parseSecretKey(secret);
  return nip19.npubEncode(getPublicKey(sk));
}

// --- wrap / unwrap (pure, offline) ------------------------------------------

// Seal `link` for `recipient` (npub/hex) as sender (nsec/hex). Returns the
// kind:1059 gift-wrap event ready to publish. `senderSecret` may be omitted to
// send anonymously with a throwaway sender key (the seal then reveals only that
// throwaway pubkey, not a stable identity).
export function wrapLink(link, recipient, senderSecret) {
  if (!link) throw new Error('nothing to share');
  const recipientPk = parsePubkey(recipient);
  const senderSk = senderSecret ? parseSecretKey(senderSecret) : generateSecretKey();
  const rumor = {
    kind: KIND_FILE_RUMOR,
    content: link,
    tags: [['k', APP_TAG]],
  };
  // nip59.wrapEvent builds rumor→seal→wrap, randomizes seal/wrap timestamps,
  // and signs the wrap with a fresh ephemeral key internally.
  return nip59.wrapEvent(rumor, senderSk, recipientPk);
}

// Open a gift wrap addressed to me (nsec/hex). Returns { link, senderPubkey }.
// Throws if the wrap is not for me or does not carry a libreshare link.
export function unwrapToLink(wrap, mySecret) {
  const mySk = parseSecretKey(mySecret);
  const rumor = nip59.unwrapEvent(wrap, mySk); // decrypts wrap→seal→rumor
  if (rumor.kind !== KIND_FILE_RUMOR) throw new Error('not a file share');
  const link = (rumor.content || '').trim();
  if (!link) throw new Error('empty share');
  return { link, senderPubkey: rumor.pubkey, npub: nip19.npubEncode(rumor.pubkey) };
}

// --- relay I/O (browser only; needs a WebSocket global) ---------------------

async function withPool(fn) {
  const { SimplePool } = await import('../vendor/nostr-tools.js');
  const pool = new SimplePool();
  try { return await fn(pool); }
  finally { /* connections are cleaned up by the caller-provided relay list */ }
}

// Publish a gift wrap to the recipient's inbox relays. Resolves with the relays
// that accepted it; throws only if every relay rejected.
export async function publishWrap(relays, wrap) {
  return withPool(async (pool) => {
    const results = await Promise.allSettled(pool.publish(relays, wrap));
    const ok = [];
    const errors = [];
    results.forEach((r, i) => {
      if (r.status === 'fulfilled') ok.push(relays[i]);
      else errors.push(`${relays[i]}: ${r.reason?.message || r.reason}`);
    });
    pool.close(relays);
    if (ok.length === 0) throw new Error(`all relays rejected: ${errors.join('; ')}`);
    return ok;
  });
}

// Fetch every gift wrap addressed to me across `relays`, unwrap the ones that
// carry a libreshare link, and return them newest-first, deduped by link.
// Wraps that fail to decrypt (not for me, or corrupt) are skipped silently.
export async function fetchWraps(relays, mySecret) {
  const mySk = parseSecretKey(mySecret);
  const myPk = getPublicKey(mySk);
  return withPool(async (pool) => {
    const events = await pool.querySync(relays, { kinds: [KIND_GIFT_WRAP], '#p': [myPk] });
    pool.close(relays);
    const out = [];
    const seen = new Set();
    for (const wrap of events) {
      let opened;
      try { opened = unwrapToLink(wrap, mySk); } catch { continue; }
      if (seen.has(opened.link)) continue;
      seen.add(opened.link);
      out.push({ ...opened, wrappedAt: wrap.created_at });
    }
    // Gift-wrap timestamps are randomized, so this order is only approximate.
    out.sort((a, b) => b.wrappedAt - a.wrappedAt);
    return out;
  });
}
