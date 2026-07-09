// The descriptor is the actual "key". In link mode the whole thing lives in the
// URL fragment (after #), which browsers never send to any server. Blossom
// servers and any gateway therefore see only the opaque ciphertext blob.

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

// { v, hash, ck, servers, realSize, meta }
export function buildDescriptor({ hash, ck, servers, realSize, meta }) {
  return {
    v: 1,
    hash,
    ck: b64urlEncode(ck),
    servers,
    realSize,
    meta: b64urlEncode(meta),
  };
}

export function encodeFragment(descriptor) {
  return b64urlEncode(new TextEncoder().encode(JSON.stringify(descriptor)));
}

export function decodeFragment(fragment) {
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

export function buildLink(origin, descriptor) {
  return `${origin}/#${encodeFragment(descriptor)}`;
}
