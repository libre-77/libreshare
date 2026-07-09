// Blossom (BUD-01/02) client. Addresses blobs by sha256 of their bytes.
// Upload mirrors to several servers so no single operator/jurisdiction is a
// single point of failure. Uploads carry a signed kind:24242 event by default
// (see nostr-auth.js); pass authFor: null for a server that takes unsigned
// writes, like the local mock. Downloads need no auth anywhere.

import { sha256Hex } from './crypto.js';
import { ephemeralUploadAuth } from './nostr-auth.js';

// The app's default mirror set. Doubles as the upload-form default and the
// download fallback when a link omits its own server list (the shorter link
// mode): a fragment with zero servers is resolved against these. Keep in sync
// with the #servers input default in index.html.
export const DEFAULT_SERVERS = ['https://blossom.band', 'https://blossom.nostr.build'];

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

// Upload to every server in parallel; require at least one success. Returns the
// servers that accepted and confirmed the expected hash, in the original order.
// Mirroring the same blob to N independent operators is what gives availability
// and censorship resistance (ARCHITECTURE.md §2); running the PUTs concurrently
// makes the wall-clock cost the slowest single mirror instead of their sum.
//
// onProgress(fraction) reports overall 0..1 = mean of each mirror's byte
// fraction. Real byte progress is only available in the browser (XHR); on the
// fetch path each mirror's slice still snaps to 1 on completion, so the callback
// stays monotonic.
export async function upload(servers, blob, expectedHash, authFor = ephemeralUploadAuth, onProgress) {
  const canXhr = typeof XMLHttpRequest !== 'undefined';
  const frac = new Array(servers.length).fill(0);
  const report = onProgress
    ? () => onProgress(frac.reduce((a, b) => a + b, 0) / servers.length)
    : null;

  const settled = await Promise.allSettled(servers.map(async (server, i) => {
    // Each mirror gets its own throwaway upload-auth key (nostr-auth.js), so a
    // fresh signature per server keeps them unable to link the uploads.
    const authHeader = authFor ? await authFor(server, expectedHash) : null;
    const onOne = report ? (f) => { frac[i] = f; report(); } : null;
    const info = (onProgress && canXhr)
      ? await putXhr(server, blob, expectedHash, authHeader, onOne)
      : await put(server, blob, expectedHash, authHeader);
    if (info.sha256 && info.sha256 !== expectedHash) {
      throw new Error(`hash mismatch from ${server}`);
    }
    if (onOne) onOne(1); // close this mirror's slice even on the fetch path
    return server;
  }));

  const ok = [];
  const errors = [];
  settled.forEach((r, i) => {
    if (r.status === 'fulfilled') ok.push(r.value);
    else errors.push(`${servers[i]}: ${r.reason?.message || r.reason}`);
  });
  if (ok.length === 0) throw new Error(`all uploads failed: ${errors.join('; ')}`);
  return ok;
}

// --- server size limit detection (BUD-06 HEAD /upload) ------------------------
// A HEAD /upload carrying X-Content-Length asks the server whether a blob of
// that size would be accepted, returning 200 (yes) or 413 (too big) WITHOUT
// transferring any bytes. We binary-search each server's ceiling so the app can
// pick a part size automatically instead of the user guessing.

const sizeCache = new Map(); // server -> max blob bytes, or null if undetectable
const PROBE_CAP = 2 * 1024 * 1024 * 1024; // stop probing past 2 GiB
const MiB = 1024 * 1024;

// Blob-size caps measured out of band (BUD-06 HEAD, 2026-07) for the servers the
// app ships with, so the common case needs no runtime probing (instant, and no
// 413 console noise from the search). Only servers absent here are probed live.
// Re-measure if a server changes its policy.
const KNOWN_LIMITS = {
  'https://blossom.band': 20 * MiB,
  'https://blossom.nostr.build': 20 * MiB,
  'https://nostr.download': 1024 * MiB, // HEAD accepts >1 GiB; conservative floor
};

const normServer = (s) => s.replace(/\/$/, '');

async function headAllows(server, size, authFor) {
  try {
    const auth = authFor ? await authFor(server, '0'.repeat(64)) : null;
    const res = await fetch(`${server.replace(/\/$/, '')}/upload`, {
      method: 'HEAD',
      headers: {
        ...(auth ? { Authorization: auth } : {}),
        'X-Content-Length': String(size),
        'X-Content-Type': 'image/png',
        'X-SHA-256': '0'.repeat(64),
      },
    });
    if (res.status === 200) return true;
    if (res.status === 413) return false;
    return null; // 401/404/… -> this server doesn't answer BUD-06 usefully
  } catch { return null; }
}

// Largest blob (bytes) a server accepts, or null if it doesn't support the HEAD
// check. Cached per session.
export async function maxUploadSize(server, authFor = ephemeralUploadAuth) {
  const key = normServer(server);
  if (KNOWN_LIMITS[key] != null) return KNOWN_LIMITS[key]; // pre-measured, no probe
  if (sizeCache.has(key)) return sizeCache.get(key);
  let result = null;
  const oneMiB = 1024 * 1024;
  const small = await headAllows(server, oneMiB, authFor);
  if (small === null) {
    result = null;                         // HEAD unusable
  } else if (small === false) {
    result = oneMiB;                       // caps below 1 MiB; treat as 1 MiB
  } else {
    let lo = oneMiB, hi = lo * 2;
    while (hi < PROBE_CAP && (await headAllows(server, hi, authFor)) === true) { lo = hi; hi *= 2; }
    if (hi >= PROBE_CAP) {
      result = PROBE_CAP;
    } else {
      while (hi - lo > oneMiB) {           // narrow to ~1 MiB
        const mid = Math.floor((lo + hi) / 2);
        if (await headAllows(server, mid, authFor)) lo = mid; else hi = mid;
      }
      result = lo;
    }
  }
  sizeCache.set(key, result);
  return result;
}

// Smallest accepted-blob limit across all targets (a part must fit every mirror).
// null if no server answered the HEAD check.
export async function detectMaxBlob(servers, authFor = ephemeralUploadAuth) {
  const limits = [];
  for (const s of servers) {
    const l = await maxUploadSize(s, authFor);
    if (l != null) limits.push(l);
  }
  return limits.length ? Math.min(...limits) : null;
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
