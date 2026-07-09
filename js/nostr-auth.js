// BUD-02 upload authorization. Public Blossom servers reject an unsigned
// PUT /upload with 401; they want an `Authorization: Nostr <base64 kind:24242>`
// header.
//
// The key that signs it is generated per upload and zeroized before this
// function returns, so a blob server sees a different pubkey for every file and
// cannot link two uploads to the same person (ARCHITECTURE.md §5). The cost is
// that BUD-02 DELETE is impossible afterwards — unlinkability over deletion is
// the deliberate trade (§9.2).
//
// Signing itself is nostr-tools (schnorr via @noble/curves); nothing crypto is
// hand-rolled here (§11).

import { finalizeEvent, generateSecretKey } from '../vendor/nostr-tools.js';

const KIND_BLOSSOM_AUTH = 24242;
const AUTH_WINDOW_SECONDS = 300;

// The event JSON is ASCII (hex hash, ascii content), so latin1 btoa is safe.
function base64(str) {
  if (typeof btoa === 'function') return btoa(str);
  return Buffer.from(str, 'binary').toString('base64');
}

export async function ephemeralUploadAuth(server, hash) {
  const now = Math.floor(Date.now() / 1000);
  const sk = generateSecretKey();
  try {
    const event = finalizeEvent(
      {
        kind: KIND_BLOSSOM_AUTH,
        created_at: now,
        content: 'Upload from miraclefile',
        tags: [
          ['t', 'upload'],
          ['x', hash],
          ['expiration', String(now + AUTH_WINDOW_SECONDS)],
        ],
      },
      sk,
    );
    return 'Nostr ' + base64(JSON.stringify(event));
  } finally {
    sk.fill(0);
  }
}
