// Run: node test/nostr.test.mjs
// Offline gift-wrap tests: wrap/unwrap round trip, sender hiding, deniability
// (unsigned rumor), recipient isolation, key parsing. No relay/network I/O.
import {
  generateIdentity, wrapLink, unwrapToLink,
  parsePubkey, parseSecretKey, npubOf,
} from '../js/nostr-share.js';

let pass = 0, fail = 0;
function ok(name, cond) {
  if (cond) { pass++; console.log(`  ok  ${name}`); }
  else { fail++; console.log(`FAIL  ${name}`); }
}
function throws(name, fn) {
  try { fn(); fail++; console.log(`FAIL  ${name} (did not throw)`); }
  catch { pass++; console.log(`  ok  ${name}`); }
}

const LINK = 'https://app.example/#eyJ2IjoxfQ_SECRET_fragment';

// 1. round trip: sealed for Bob, Bob recovers the exact link
{
  const alice = generateIdentity();
  const bob = generateIdentity();
  const wrap = wrapLink(LINK, bob.npub, alice.nsec);
  ok('wrap is kind:1059', wrap.kind === 1059);
  ok('wrap pubkey is ephemeral (not sender)', wrap.pubkey !== alice.pubkeyHex);
  ok('wrap p-tags the recipient', wrap.tags.some((t) => t[0] === 'p' && t[1] === bob.pubkeyHex));
  ok('wrap content is encrypted (no plaintext link)', !wrap.content.includes('SECRET'));

  const opened = unwrapToLink(wrap, bob.nsec);
  ok('link recovered exactly', opened.link === LINK);
  ok('recipient learns real sender', opened.npub === alice.npub);
}

// 2. deniability: the inner rumor is unsigned
{
  const alice = generateIdentity();
  const bob = generateIdentity();
  const wrap = wrapLink(LINK, bob.npub, alice.nsec);
  const mySk = parseSecretKey(bob.nsec);
  const { unwrapEvent } = await import('../vendor/nostr-tools.js').then((m) => m.nip59);
  const rumor = unwrapEvent(wrap, mySk);
  ok('rumor has no signature', rumor.sig === undefined);
}

// 3. recipient isolation: a stranger cannot open the wrap
{
  const bob = generateIdentity();
  const eve = generateIdentity();
  const wrap = wrapLink(LINK, bob.npub);
  throws('stranger cannot unwrap', () => unwrapToLink(wrap, eve.nsec));
}

// 4. anonymous send: no sender secret -> throwaway sender key
{
  const alice = generateIdentity();
  const bob = generateIdentity();
  const wrap = wrapLink(LINK, bob.npub); // no sender
  const opened = unwrapToLink(wrap, bob.nsec);
  ok('anon link recovered', opened.link === LINK);
  ok('anon sender is not a stable identity', opened.npub !== alice.npub);
}

// 5. two wraps of the same link are unlinkable at the wrap layer
{
  const bob = generateIdentity();
  const w1 = wrapLink(LINK, bob.npub);
  const w2 = wrapLink(LINK, bob.npub);
  ok('distinct ephemeral wrap pubkeys', w1.pubkey !== w2.pubkey);
  ok('distinct wrap ciphertexts', w1.content !== w2.content);
  ok('both still open to the same link',
    unwrapToLink(w1, bob.nsec).link === LINK && unwrapToLink(w2, bob.nsec).link === LINK);
}

// 6. key parsing: npub/nsec bech32 and raw hex both accepted; wrong type rejected
{
  const id = generateIdentity();
  ok('npubOf(nsec) matches identity', npubOf(id.nsec) === id.npub);
  const pkHex = parsePubkey(id.npub);
  ok('parsePubkey returns 64-hex', /^[0-9a-f]{64}$/.test(pkHex));
  ok('parsePubkey accepts raw hex too', parsePubkey(pkHex) === pkHex);
  ok('parseSecretKey returns 32 bytes', parseSecretKey(id.nsec).length === 32);
  throws('npub rejected where nsec expected', () => parseSecretKey(id.npub));
  throws('nsec rejected where npub expected', () => parsePubkey(id.nsec));
}

// 7. empty link is refused up front
{
  const bob = generateIdentity();
  throws('empty link rejected', () => wrapLink('', bob.npub));
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
