// Client-side file encryption. Servers never see plaintext or keys.
//
// Construction (current, header version 2): XChaCha20-Poly1305 via libsodium's
// crypto_secretstream_xchacha20poly1305 — the audited STREAM (Hoang-Reyhanitabar-
// Rogaway) implementation, so chunk framing, the truncation-detecting final tag,
// and the extended 192-bit nonce are all handled by the library instead of
// hand-rolled here. Per-part subkeys come from crypto_kdf_derive_from_key
// (BLAKE2b-based KDF built for exactly this: deriving subkey N from a master
// key) instead of a hand-rolled HKDF construction. See vendor/libsodium.js.
//
// Header version 1 (legacy) is kept read-only so files shared before this
// change keep decrypting: AES-256-GCM (the native Web Crypto AEAD; Web Crypto
// has no XChaCha20-Poly1305) in the same hand-rolled STREAM framing this file
// used before — a counter+final-flag nonce, verified in the "legacy" functions
// below. New uploads never produce a version-1 blob.

import sodium from '../vendor/libsodium.js';

await sodium.ready;

const MAGIC = new Uint8Array([0x4d, 0x46, 0x49, 0x4c]); // "MFIL"
const LEGACY_VERSION = 1; // AES-256-GCM, hand-rolled STREAM framing (read-only)
const VERSION = 2;        // XChaCha20-Poly1305 via libsodium secretstream (current)

// A valid 1x1 transparent PNG. The encrypted blob rides AFTER its IEND so the
// stored bytes begin with a real PNG signature. Public Blossom servers are
// media CDNs that sniff the body and 415 anything that isn't an image; a PNG
// preamble gets ciphertext past them (matched by Content-Type: image/png).
// Image decoders ignore trailing bytes, and blobs are content-addressed, so a
// server that returns the bytes unchanged round-trips. A server that transcodes
// the "image" corrupts the tail — the sha256 check on download rejects it and
// the next mirror is tried.
const PNG_STUB = Uint8Array.from(
  atob('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=='),
  (c) => c.charCodeAt(0),
);
const HEADER_LEN = 9; // MAGIC(4) | version(1) | chunkSize(4 BE)
const CHUNK = 256 * 1024; // plaintext bytes per chunk
const LEGACY_TAG = 16; // legacy AES-GCM tag bytes
const MAX_CHUNKS = 0xffffffff; // 32-bit counter ceiling (legacy nonce; kept as a sanity bound for both)

const KiB = 1024;
const MIN_PAD = 64 * KiB;   // floor: tiny files all bucket here (cheap anonymity)
const PAD_BITS = 3;         // keep this many significant bits -> overhead <= 2^-3

// Subkey derivation contexts (crypto_kdf_derive_from_key requires exactly 8
// bytes). Content parts use the part index as the subkey id; meta uses a fixed
// id under its own context, so it can never collide with a content subkey even
// at id 0.
const KDF_CONTEXT_CONTENT = 'MFILv2ct';
const KDF_CONTEXT_META = 'MFILv2mt';

const subtle = globalThis.crypto.subtle;
const utf8 = new TextEncoder();
const utf8d = new TextDecoder();

// Best-effort scrub of a byte buffer's contents. JS gives no guarantee (the GC
// may have already copied it, and strings are immutable and cannot be wiped at
// all), but overwriting the Uint8Array we control removes the most obvious
// residue of a key or plaintext from the heap. No-op for anything non-array.
export function wipe(bytes) {
  if (bytes instanceof Uint8Array) bytes.fill(0);
}

export function randomBytes(n) {
  // getRandomValues rejects requests over 65,536 bytes, so fill in slices.
  const out = new Uint8Array(n);
  for (let o = 0; o < n; o += 65536) {
    globalThis.crypto.getRandomValues(out.subarray(o, Math.min(o + 65536, n)));
  }
  return out;
}

// Pad the true length up so the stored size leaks only a bucket, not the exact
// byte count — but bound the waste. Files at or below MIN_PAD all round to
// MIN_PAD (a shared bucket for small files). Above it, round up to a step that
// keeps the top PAD_BITS significant bits, so the padding overhead is at most
// 2^-PAD_BITS (12.5% at PAD_BITS=3). This replaces the old power-of-two ladder,
// whose next-step rounding could nearly double a file (33 MiB -> 64 MiB) and
// tip it over a server's size cap. The trade is a finer size bucket, i.e. a bit
// more size information leaks than with the coarse ladder.
export function paddedLength(len) {
  if (len <= MIN_PAD) return MIN_PAD;
  const step = 2 ** Math.max(0, Math.floor(Math.log2(len)) - PAD_BITS);
  return Math.ceil(len / step) * step;
}

async function hkdfLegacy(ikm, info, length = 32) {
  const key = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: utf8.encode(info) },
    key, length * 8,
  );
  return new Uint8Array(bits);
}

// Legacy (header v1) per-part content key: HKDF-SHA256 via Web Crypto, then
// imported as an AES-GCM key. Part 0 keeps the original info string so an old
// single-part file is byte-identical to the pre-multipart format.
async function contentKeyLegacy(ck, part = 0) {
  const info = part === 0 ? 'miraclefile/v1/content' : `miraclefile/v1/content/${part}`;
  const raw = await hkdfLegacy(ck, info);
  return subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

async function metaKeyLegacy(ck) {
  const raw = await hkdfLegacy(ck, 'miraclefile/v1/meta');
  return subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

// Current (header v2) per-part content subkey: crypto_kdf_derive_from_key,
// keyed on the part index. A multipart upload re-uses the secretstream framing
// from a fresh state per part, so every part MUST derive under a distinct
// subkey — this is what crypto_kdf's subkey-id parameter is for.
function contentKeySodium(ck, part = 0) {
  return sodium.crypto_kdf_derive_from_key(32, part, KDF_CONTEXT_CONTENT, ck);
}

function metaKeySodium(ck) {
  return sodium.crypto_kdf_derive_from_key(32, 0, KDF_CONTEXT_META, ck);
}

export function newContentKey() {
  return randomBytes(32);
}

function legacyNonce(counter, final) {
  const n = new Uint8Array(12);
  new DataView(n.buffer).setUint32(7, counter, false);
  n[11] = final ? 1 : 0;
  return n;
}

// Remove the PNG preamble if present. A blob whose MFIL header sits at offset 0
// (older uploads, or a server that stripped the shell) passes through untouched.
function stripPngStub(blob) {
  if (blob.length >= PNG_STUB.length + HEADER_LEN
    && PNG_STUB.every((b, i) => blob[i] === b)) {
    return blob.subarray(PNG_STUB.length);
  }
  return blob;
}

function header(version) {
  const h = new Uint8Array(HEADER_LEN);
  h.set(MAGIC, 0);
  h[4] = version;
  new DataView(h.buffer).setUint32(5, CHUNK, false);
  return h;
}

function concat(parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export function toHex(bytes) {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

export async function sha256Hex(bytes) {
  const d = await subtle.digest('SHA-256', bytes);
  return toHex(new Uint8Array(d));
}

// --- meta (name/mime) --------------------------------------------------------

async function encryptMetaLegacy(ck, obj) {
  const key = await metaKeyLegacy(ck);
  const iv = randomBytes(12);
  const ct = new Uint8Array(await subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: 128 }, key, utf8.encode(JSON.stringify(obj)),
  ));
  return concat([iv, ct]);
}

async function decryptMetaLegacy(ck, blob) {
  const key = await metaKeyLegacy(ck);
  const iv = blob.subarray(0, 12);
  const ct = blob.subarray(12);
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, ct);
  return JSON.parse(utf8d.decode(pt));
}

function encryptMetaSodium(ck, obj) {
  const key = metaKeySodium(ck);
  const nonce = randomBytes(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const pt = utf8.encode(JSON.stringify(obj));
  const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(pt, null, null, nonce, key);
  wipe(key);
  return concat([nonce, ct]);
}

function decryptMetaSodium(ck, blob) {
  const nonce = blob.subarray(0, sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const ct = blob.subarray(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const key = metaKeySodium(ck);
  let pt;
  try {
    pt = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ct, null, nonce, key);
  } finally {
    wipe(key);
  }
  return JSON.parse(utf8d.decode(pt));
}

// Build the encrypted {name, mime} descriptor field (Uint8Array). Always
// current-format (header v2 scheme) — new uploads never produce legacy meta.
export function encryptMetaField(ck, name, mime) {
  return encryptMetaSodium(ck, { name, mime });
}

// Decrypt a descriptor's meta field. `v` is the descriptor version (see
// descriptor.js): 2/3 are legacy (AES-GCM) links minted before this change, 4/5
// are current (libsodium) links. The descriptor version is read up front by
// decodeFragment, so this dispatch is exact — not a guess from the bytes.
export async function readMeta(ck, meta, v) {
  return (v === 2 || v === 3) ? decryptMetaLegacy(ck, meta) : decryptMetaSodium(ck, meta);
}

// --- content (bulk plaintext) -------------------------------------------------

async function encryptPartLegacy(plain, ck, part, onProgress) {
  const key = await contentKeyLegacy(ck, part);
  const realSize = plain.length;

  const padded = new Uint8Array(paddedLength(realSize));
  padded.set(plain);

  const aad = header(LEGACY_VERSION);
  const nChunks = Math.max(1, Math.ceil(padded.length / CHUNK));
  if (nChunks > MAX_CHUNKS) throw new Error('part too large');

  const parts = [PNG_STUB, aad];
  for (let i = 0; i < nChunks; i++) {
    const slice = padded.subarray(i * CHUNK, Math.min((i + 1) * CHUNK, padded.length));
    const final = i === nChunks - 1;
    const ct = await subtle.encrypt(
      { name: 'AES-GCM', iv: legacyNonce(i, final), additionalData: aad, tagLength: 128 },
      key, slice,
    );
    parts.push(new Uint8Array(ct));
    if (onProgress) onProgress((i + 1) / nChunks);
  }

  const blob = concat(parts);
  const blobHash = await sha256Hex(blob);
  wipe(padded); // the padded buffer held plaintext; scrub it
  return { blob, blobHash, realSize };
}

// Kept only so tests (and any not-yet-downloaded old link) can exercise header
// v1 decrypt. New uploads must never call this — use encryptPart.
export async function encryptPartLegacyForTests(plain, ck, part, onProgress) {
  return encryptPartLegacy(plain, ck, part, onProgress);
}

async function encryptPartSodium(plain, ck, part, onProgress) {
  const key = contentKeySodium(ck, part);
  const realSize = plain.length;

  const padded = new Uint8Array(paddedLength(realSize));
  padded.set(plain);

  const aad = header(VERSION);
  const { state, header: ssHeader } = sodium.crypto_secretstream_xchacha20poly1305_init_push(key);
  const nChunks = Math.max(1, Math.ceil(padded.length / CHUNK));
  if (nChunks > MAX_CHUNKS) throw new Error('part too large');

  const parts = [PNG_STUB, aad, ssHeader];
  for (let i = 0; i < nChunks; i++) {
    const slice = padded.subarray(i * CHUNK, Math.min((i + 1) * CHUNK, padded.length));
    const final = i === nChunks - 1;
    const tag = final
      ? sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
      : sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
    const ct = sodium.crypto_secretstream_xchacha20poly1305_push(state, slice, aad, tag);
    parts.push(ct);
    if (onProgress) onProgress((i + 1) / nChunks);
  }

  const blob = concat(parts);
  const blobHash = await sha256Hex(blob);
  wipe(padded); // the padded buffer held plaintext; scrub it
  wipe(key);
  return { blob, blobHash, realSize };
}

// Encrypt one plaintext part into an uploadable blob under CK's `part` subkey.
// Returns { blob, blobHash, realSize }. Single-blob uploads use part 0; a
// multipart upload calls this once per slice with an increasing part index.
// Always produces the current (header v2, libsodium) format.
export async function encryptPart(plain, ck, part, onProgress) {
  return encryptPartSodium(plain, ck, part, onProgress);
}

async function decryptPartToSinkLegacy(body, aad, chunkSize, ck, part, realSize, sink, onProgress) {
  const key = await contentKeyLegacy(ck, part);
  const encChunk = chunkSize + LEGACY_TAG;
  const nChunks = Math.max(1, Math.ceil(body.length / encChunk));

  let written = 0;
  for (let i = 0; i < nChunks; i++) {
    const slice = body.subarray(i * encChunk, Math.min((i + 1) * encChunk, body.length));
    const final = i === nChunks - 1;
    const ptBuf = await subtle.decrypt(
      { name: 'AES-GCM', iv: legacyNonce(i, final), additionalData: aad, tagLength: 128 },
      key, slice,
    );
    const pt = new Uint8Array(ptBuf);
    const remaining = realSize - written;
    if (remaining > 0) await sink(pt.length <= remaining ? pt : pt.subarray(0, remaining));
    written += pt.length;
    wipe(pt);
    if (onProgress) onProgress((i + 1) / nChunks);
  }
}

async function decryptPartToSinkSodium(body, aad, chunkSize, ck, part, realSize, sink, onProgress) {
  const headerLen = sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES;
  if (body.length < headerLen) throw new Error('blob too short');
  const ssHeader = body.subarray(0, headerLen);
  const rest = body.subarray(headerLen);

  const key = contentKeySodium(ck, part);
  let state;
  try {
    state = sodium.crypto_secretstream_xchacha20poly1305_init_pull(ssHeader, key);
  } finally {
    wipe(key);
  }
  const encChunk = chunkSize + sodium.crypto_secretstream_xchacha20poly1305_ABYTES;
  const nChunks = Math.max(1, Math.ceil(rest.length / encChunk));

  let written = 0;
  for (let i = 0; i < nChunks; i++) {
    const slice = rest.subarray(i * encChunk, Math.min((i + 1) * encChunk, rest.length));
    const final = i === nChunks - 1;
    // pull() authenticates the chunk AND its embedded tag byte together, so an
    // attacker cannot forge TAG_FINAL on a dropped/truncated stream without
    // breaking the MAC — this is the same truncation defense the legacy path
    // built from a hand-rolled nonce flag, but native to the STREAM construction.
    const { message, tag } = sodium.crypto_secretstream_xchacha20poly1305_pull(state, slice, aad);
    if (final !== (tag === sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL)) {
      throw new Error('stream truncated or extended');
    }
    const remaining = realSize - written;
    if (remaining > 0) await sink(message.length <= remaining ? message : message.subarray(0, remaining));
    written += message.length;
    wipe(message);
    if (onProgress) onProgress((i + 1) / nChunks);
  }
}

// Decrypt one part's blob under CK's `part` subkey, streaming plaintext to
// sink(Uint8Array) chunk by chunk. Throws on any authentication failure (tamper,
// truncation, wrong key). onProgress reports this part's own 0..1. Dispatches
// on the blob's own header version byte, so header-v1 (legacy AES-GCM) blobs
// from before this change still decrypt.
export async function decryptPartToSink(blob, ck, part, realSize, sink, onProgress) {
  blob = stripPngStub(blob);
  if (blob.length < HEADER_LEN) throw new Error('blob too short');
  const aad = blob.subarray(0, HEADER_LEN);
  for (let i = 0; i < 4; i++) if (aad[i] !== MAGIC[i]) throw new Error('bad magic');
  const version = aad[4];
  const chunkSize = new DataView(aad.buffer, aad.byteOffset).getUint32(5, false);
  const body = blob.subarray(HEADER_LEN);

  if (version === LEGACY_VERSION) {
    return decryptPartToSinkLegacy(body, aad, chunkSize, ck, part, realSize, sink, onProgress);
  }
  if (version === VERSION) {
    return decryptPartToSinkSodium(body, aad, chunkSize, ck, part, realSize, sink, onProgress);
  }
  throw new Error('unsupported version');
}

// Single-part convenience wrapper (part 0), keeping the pre-multipart signature.
export async function decryptToSink(blob, ck, realSize, sink, onProgress) {
  return decryptPartToSink(blob, ck, 0, realSize, sink, onProgress);
}

export async function decryptBytes(blob, ck, realSize) {
  const parts = [];
  await decryptToSink(blob, ck, realSize, (p) => parts.push(p.slice()));
  return concat(parts);
}

// Encrypt plaintext bytes into a single uploadable blob (part 0).
// Returns { blob, blobHash, ck, realSize, meta }. Convenience wrapper over
// encryptPart for the common single-part case; ck is a fresh 32-byte key.
export async function encryptBytes(plain, name, mime, onProgress) {
  const ck = newContentKey();
  const { blob, blobHash, realSize } = await encryptPart(plain, ck, 0, onProgress);
  const meta = await encryptMetaField(ck, name, mime);
  return { blob, blobHash, ck, realSize, meta };
}
