// The descriptor is the actual "key". In link mode the whole thing lives in the
// URL fragment (after #), which browsers never send to any server. Blossom
// servers and any gateway therefore see only the opaque ciphertext blob.
//
// The fragment is a binary pack (v2), not JSON — dropping the JSON key names,
// quotes, and the hex hash (stored raw) keeps the link ~40% shorter than the
// equivalent JSON. Layout, then base64url:
//
//   [0]      version = 2
//   [1..32]  blob hash (raw sha256, 32 bytes)
//   [33..64] content key CK (32 bytes)
//   [..]     realSize        (unsigned LEB128 varint)
//   [..]     meta length     (varint) then meta bytes (encrypted {name,mime})
//   [..]     server count    (1 byte) then per server: length (varint) + utf8
//
// A v1 descriptor was base64url(JSON), whose first byte is '{' (0x7b). decode
// dispatches on that first byte, so links minted before this change still open.

export function b64urlEncode(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function b64urlDecode(str) {
  const s = str.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(s + '==='.slice((s.length + 3) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const VERSION = 2;
const JSON_FIRST_BYTE = 0x7b; // '{' — a legacy v1 (JSON) fragment

// Unsigned LEB128. Arithmetic (not bit ops) so realSize past 2^31 stays exact.
function pushVarint(out, n) {
  if (n < 0 || !Number.isFinite(n)) throw new Error('bad length');
  while (n > 0x7f) { out.push((n & 0x7f) | 0x80); n = Math.floor(n / 128); }
  out.push(n & 0x7f);
}
function readVarint(bytes, pos) {
  let n = 0, mul = 1, b;
  do {
    if (pos.i >= bytes.length) throw new Error('truncated descriptor');
    b = bytes[pos.i++];
    n += (b & 0x7f) * mul;
    mul *= 128;
  } while (b & 0x80);
  return n;
}

const HEX = /^[0-9a-f]{64}$/i;
function hexToBytes(hex) {
  if (!HEX.test(hex)) throw new Error('hash must be 64 hex chars');
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
function bytesToHex(bytes) {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

// { v, hash, ck, servers, realSize, meta } — ck and meta stay raw Uint8Arrays;
// they are packed by encodeFragment, so the caller may wipe() them afterwards.
export function buildDescriptor({ hash, ck, servers, realSize, meta }) {
  return { v: VERSION, hash, ck, servers, realSize, meta };
}

export function encodeFragment(descriptor) {
  const { hash, ck, servers, realSize, meta } = descriptor;
  if (ck.length !== 32) throw new Error('ck must be 32 bytes');
  const enc = new TextEncoder();
  const out = [VERSION];
  for (const b of hexToBytes(hash)) out.push(b);
  for (const b of ck) out.push(b);
  pushVarint(out, realSize);
  pushVarint(out, meta.length);
  for (const b of meta) out.push(b);
  if (servers.length > 255) throw new Error('too many servers');
  out.push(servers.length);
  for (const s of servers) {
    const sb = enc.encode(s);
    pushVarint(out, sb.length);
    for (const b of sb) out.push(b);
  }
  return b64urlEncode(Uint8Array.from(out));
}

function decodeBinary(bytes) {
  const pos = { i: 1 }; // skip version byte
  const hash = bytesToHex(bytes.subarray(pos.i, pos.i + 32)); pos.i += 32;
  const ck = bytes.slice(pos.i, pos.i + 32); pos.i += 32;
  if (ck.length !== 32) throw new Error('truncated descriptor');
  const realSize = readVarint(bytes, pos);
  const metaLen = readVarint(bytes, pos);
  const meta = bytes.slice(pos.i, pos.i + metaLen); pos.i += metaLen;
  if (meta.length !== metaLen) throw new Error('truncated descriptor');
  const count = bytes[pos.i++];
  const dec = new TextDecoder();
  const servers = [];
  for (let k = 0; k < count; k++) {
    const len = readVarint(bytes, pos);
    servers.push(dec.decode(bytes.subarray(pos.i, pos.i + len)));
    pos.i += len;
  }
  return { v: VERSION, hash, ck, servers, realSize, meta };
}

// Legacy v1: base64url(JSON). Kept so links shared before the binary format
// still resolve.
function decodeJsonV1(fragment) {
  const json = new TextDecoder().decode(b64urlDecode(fragment));
  const d = JSON.parse(json);
  if (d.v !== 1) throw new Error('unsupported descriptor version');
  return {
    v: d.v,
    hash: d.hash,
    ck: b64urlDecode(d.ck),
    servers: d.servers,
    realSize: d.realSize,
    meta: b64urlDecode(d.meta),
  };
}

export function decodeFragment(fragment) {
  const bytes = b64urlDecode(fragment);
  if (bytes[0] === JSON_FIRST_BYTE) return decodeJsonV1(fragment);
  if (bytes[0] === VERSION) return decodeBinary(bytes);
  throw new Error('unsupported descriptor version');
}

export function buildLink(origin, descriptor) {
  return `${origin}/#${encodeFragment(descriptor)}`;
}
