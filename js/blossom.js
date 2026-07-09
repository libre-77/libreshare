// Blossom (BUD-01/02) client. Addresses blobs by sha256 of their bytes.
// Upload mirrors to several servers so no single operator/jurisdiction is a
// single point of failure. Uploads carry a signed kind:24242 event by default
// (see nostr-auth.js); pass authFor: null for a server that takes unsigned
// writes, like the local mock. Downloads need no auth anywhere.

import { sha256Hex } from './crypto.js';
import { ephemeralUploadAuth } from './nostr-auth.js';

// The blob starts with a real 1x1 PNG (crypto.js PNG_STUB) with ciphertext after
// its IEND, so image/png here matches the sniffed magic and media-CDN Blossom
// servers accept it. X-SHA-256 lets a server verify the address without hashing.
async function put(server, blob, expectedHash, authHeader) {
  const headers = { 'Content-Type': 'image/png' };
  if (expectedHash) headers['X-SHA-256'] = expectedHash;
  if (authHeader) headers['Authorization'] = authHeader;
  const res = await fetch(`${server.replace(/\/$/, '')}/upload`, {
    method: 'PUT', headers, body: blob,
  });
  if (!res.ok) throw new Error(`upload ${server} -> ${res.status}`);
  return res.json().catch(() => ({}));
}

// Upload to every server; require at least one success. Returns servers that
// accepted and confirmed the expected hash.
export async function upload(servers, blob, expectedHash, authFor = ephemeralUploadAuth) {
  const ok = [];
  const errors = [];
  for (const server of servers) {
    try {
      const authHeader = authFor ? await authFor(server, expectedHash) : null;
      const info = await put(server, blob, expectedHash, authHeader);
      if (info.sha256 && info.sha256 !== expectedHash) {
        throw new Error(`hash mismatch from ${server}`);
      }
      ok.push(server);
    } catch (e) {
      errors.push(e.message);
    }
  }
  if (ok.length === 0) throw new Error(`all uploads failed: ${errors.join('; ')}`);
  return ok;
}

// Try each mirror until one returns bytes whose sha256 matches. A server that
// serves the wrong bytes is detected and skipped.
export async function download(servers, hash, onProgress) {
  const errors = [];
  for (const server of servers) {
    try {
      const res = await fetch(`${server.replace(/\/$/, '')}/${hash}`);
      if (!res.ok) throw new Error(`${res.status}`);
      const buf = new Uint8Array(await res.arrayBuffer());
      const got = await sha256Hex(buf);
      if (got !== hash) throw new Error('content hash mismatch');
      if (onProgress) onProgress(1);
      return buf;
    } catch (e) {
      errors.push(`${server}: ${e.message}`);
    }
  }
  throw new Error(`all downloads failed: ${errors.join('; ')}`);
}
