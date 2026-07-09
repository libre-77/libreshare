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

// XHR variant, used only in the browser when a progress callback is supplied:
// fetch() cannot report request-upload progress, but XHR's upload.onprogress
// can. onProgress receives a 0..1 fraction of this blob's bytes sent.
function putXhr(server, blob, expectedHash, authHeader, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('PUT', `${server.replace(/\/$/, '')}/upload`);
    xhr.setRequestHeader('Content-Type', 'image/png');
    if (expectedHash) xhr.setRequestHeader('X-SHA-256', expectedHash);
    if (authHeader) xhr.setRequestHeader('Authorization', authHeader);
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable && onProgress) onProgress(e.loaded / e.total);
    };
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        let info = {};
        try { info = JSON.parse(xhr.responseText); } catch { /* empty body ok */ }
        resolve(info);
      } else reject(new Error(`upload ${server} -> ${xhr.status}`));
    };
    xhr.onerror = () => reject(new Error(`upload ${server} -> network error`));
    xhr.send(blob);
  });
}

// Upload to every server; require at least one success. Returns servers that
// accepted and confirmed the expected hash. onProgress(fraction) reports overall
// 0..1 across all mirrors (server i contributes its byte fraction of 1/N), and
// is only wired to real byte progress in the browser (XHR); elsewhere it still
// ticks once per completed server so callers get monotonic feedback.
export async function upload(servers, blob, expectedHash, authFor = ephemeralUploadAuth, onProgress) {
  const ok = [];
  const errors = [];
  const canXhr = typeof XMLHttpRequest !== 'undefined';
  for (let i = 0; i < servers.length; i++) {
    const server = servers[i];
    const report = onProgress ? (f) => onProgress((i + f) / servers.length) : null;
    try {
      const authHeader = authFor ? await authFor(server, expectedHash) : null;
      const info = (onProgress && canXhr)
        ? await putXhr(server, blob, expectedHash, authHeader, report)
        : await put(server, blob, expectedHash, authHeader);
      if (info.sha256 && info.sha256 !== expectedHash) {
        throw new Error(`hash mismatch from ${server}`);
      }
      ok.push(server);
    } catch (e) {
      errors.push(e.message);
    }
    if (report) report(1); // close out this server's slice even on the fetch path
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
