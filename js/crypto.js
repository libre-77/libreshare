// Client-side file encryption. Servers never see plaintext or keys.
//
// Construction: AES-256-GCM in a STREAM (Hoang-Reyhanitabar-Rogaway) framing.
// Web Crypto has no XChaCha20-Poly1305; AES-256-GCM is the native AEAD and was
// Firefox Send's actual choice. Per-file random content key (CK) means the
// deterministic counter nonce never repeats across files.
//
// Nonce (12 bytes): [0..6]=0, [7..10]=big-endian chunk counter, [11]=final flag.
// The final flag gives truncation protection: the last chunk is sealed with
// flag=1, every other with flag=0. Dropping or appending a chunk flips a flag
// the decryptor expects and GCM authentication fails.

const MAGIC = new Uint8Array([0x4d, 0x46, 0x49, 0x4c]); // "MFIL"
const VERSION = 1;

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
const TAG = 16;
const MAX_CHUNKS = 0xffffffff; // 32-bit counter ceiling

const KiB = 1024, MiB = 1024 * 1024;
const LADDER = [
  64 * KiB, 128 * KiB, 256 * KiB, 512 * KiB,
  1 * MiB, 2 * MiB, 4 * MiB, 8 * MiB, 16 * MiB, 32 * MiB, 64 * MiB,
];

const subtle = globalThis.crypto.subtle;
const utf8 = new TextEncoder();
const utf8d = new TextDecoder();

export function randomBytes(n) {
  // getRandomValues rejects requests over 65,536 bytes, so fill in slices.
  const out = new Uint8Array(n);
  for (let o = 0; o < n; o += 65536) {
    globalThis.crypto.getRandomValues(out.subarray(o, Math.min(o + 65536, n)));
  }
  return out;
}

// Pad true length up to the next ladder step (or next 64 MiB above the ladder)
// so stored size leaks only a coarse bucket, not the exact byte count.
export function paddedLength(len) {
  for (const step of LADDER) if (len <= step) return step;
  return Math.ceil(len / (64 * MiB)) * (64 * MiB);
}

async function hkdf(ikm, info, length = 32) {
  const key = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: utf8.encode(info) },
    key, length * 8,
  );
  return new Uint8Array(bits);
}

async function contentKey(ck) {
  const raw = await hkdf(ck, 'miraclefile/v1/content');
  return subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

async function metaKeyOf(ck) {
  const raw = await hkdf(ck, 'miraclefile/v1/meta');
  return subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

function nonce(counter, final) {
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

function header() {
  const h = new Uint8Array(HEADER_LEN);
  h.set(MAGIC, 0);
  h[4] = VERSION;
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

async function encryptMeta(ck, obj) {
  const key = await metaKeyOf(ck);
  const iv = randomBytes(12);
  const ct = new Uint8Array(await subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: 128 }, key, utf8.encode(JSON.stringify(obj)),
  ));
  return concat([iv, ct]);
}

async function decryptMeta(ck, blob) {
  const key = await metaKeyOf(ck);
  const iv = blob.subarray(0, 12);
  const ct = blob.subarray(12);
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, ct);
  return JSON.parse(utf8d.decode(pt));
}

// Encrypt plaintext bytes into an uploadable blob.
// Returns { blob, blobHash, ck, realSize, meta } — meta is the encrypted
// {name, mime} descriptor field (Uint8Array). ck is the 32-byte content key.
export async function encryptBytes(plain, name, mime, onProgress) {
  const ck = randomBytes(32);
  const key = await contentKey(ck);
  const realSize = plain.length;

  const padded = new Uint8Array(paddedLength(realSize));
  padded.set(plain);

  const aad = header();
  const nChunks = Math.max(1, Math.ceil(padded.length / CHUNK));
  if (nChunks > MAX_CHUNKS) throw new Error('file too large');

  const parts = [PNG_STUB, aad];
  for (let i = 0; i < nChunks; i++) {
    const slice = padded.subarray(i * CHUNK, Math.min((i + 1) * CHUNK, padded.length));
    const final = i === nChunks - 1;
    const ct = await subtle.encrypt(
      { name: 'AES-GCM', iv: nonce(i, final), additionalData: aad, tagLength: 128 },
      key, slice,
    );
    parts.push(new Uint8Array(ct));
    if (onProgress) onProgress((i + 1) / nChunks);
  }

  const blob = concat(parts);
  const blobHash = await sha256Hex(blob);
  const meta = await encryptMeta(ck, { name, mime });
  return { blob, blobHash, ck, realSize, meta };
}

// Decrypt a blob, streaming plaintext to sink(Uint8Array) chunk by chunk.
// Throws on any authentication failure (tamper, truncation, wrong key).
export async function decryptToSink(blob, ck, realSize, sink, onProgress) {
  blob = stripPngStub(blob);
  if (blob.length < HEADER_LEN) throw new Error('blob too short');
  const aad = blob.subarray(0, HEADER_LEN);
  for (let i = 0; i < 4; i++) if (aad[i] !== MAGIC[i]) throw new Error('bad magic');
  if (aad[4] !== VERSION) throw new Error('unsupported version');
  const chunkSize = new DataView(aad.buffer, aad.byteOffset).getUint32(5, false);

  const key = await contentKey(ck);
  const body = blob.subarray(HEADER_LEN);
  const encChunk = chunkSize + TAG;
  const nChunks = Math.max(1, Math.ceil(body.length / encChunk));

  let written = 0;
  for (let i = 0; i < nChunks; i++) {
    const slice = body.subarray(i * encChunk, Math.min((i + 1) * encChunk, body.length));
    const final = i === nChunks - 1;
    const ptBuf = await subtle.decrypt(
      { name: 'AES-GCM', iv: nonce(i, final), additionalData: aad, tagLength: 128 },
      key, slice,
    );
    const pt = new Uint8Array(ptBuf);
    const remaining = realSize - written;
    if (remaining > 0) sink(pt.length <= remaining ? pt : pt.subarray(0, remaining));
    written += pt.length;
    if (onProgress) onProgress((i + 1) / nChunks);
  }
}

export async function decryptBytes(blob, ck, realSize) {
  const parts = [];
  await decryptToSink(blob, ck, realSize, (p) => parts.push(p.slice()));
  return concat(parts);
}

export async function readMeta(ck, meta) {
  return decryptMeta(ck, meta);
}
