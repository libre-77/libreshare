# miraclefile

End-to-end encrypted file upload/share. Files are encrypted in the browser; the
storage server holds ciphertext only and never sees a key. Vanilla JS, no build
step, no framework.

Full design (duress vaults, self-run inbox relay, Sia-backed storage) is in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). This repo ships the working core,
including Nostr gift-wrap delivery.

## What works now

- **Client-side encryption** — per-file 256-bit content key, AES-256-GCM in a
  STREAM framing (counter nonce + final-chunk flag). Truncation, reorder, and
  tamper are all caught by authentication. Size padding hides the exact length.
- **Blossom storage** — content-addressed by sha256, mirrors to several servers.
  Downloads verify the hash, so a server serving wrong bytes is rejected.
- **Unlinkable uploads** — each `PUT /upload` carries a BUD-02 `kind:24242` event
  signed by a fresh key that is zeroized right after. A server sees a different
  pubkey per file and cannot tie two uploads together. The trade is that BUD-02
  `DELETE` is then impossible; TTL expiry is the only recall.
- **Link-mode sharing** — the key + descriptor live in the URL fragment (after
  `#`), which the browser never transmits. Servers see only opaque ciphertext.
- **Nostr gift-wrap delivery** — the link *is* a key, so rather than pasting it
  into a plaintext channel it can be sealed into a NIP-59 gift wrap (kind:1059)
  addressed to one recipient and published to their inbox relay. The relay sees
  only an encrypted blob from a throwaway pubkey at a randomized time — not the
  link, not who sent it. The inner rumor is unsigned, so a recipient who leaks it
  cannot prove who sent it (deniability). The **inbox** view fetches and unwraps
  locally with the recipient's nsec.
- **Streaming decrypt** — straight to disk via the File System Access API where
  available, otherwise a buffered download.

## Not in this build (see architecture doc)

Duress vaults and a self-run inbox relay (the default relays are public). The
`docs/ARCHITECTURE.md` threat model requires these before any real high-threat
use.

Transport is plain HTTPS and the app is transport-agnostic: it does not check
for or require a Tor circuit. Client IP is therefore visible to storage servers
and to a network observer. Route the browser through Tor or a VPN yourself if
that matters; `.onion` hosts work in the server list as-is.

## Servers

Defaults are `https://blossom.band` and `https://blossom.nostr.build` — two
independent operators, so a single seizure doesn't take the file down.

Most public Blossom servers are media CDNs that sniff the body and reject raw
ciphertext with 415. To get past that, the encrypted blob rides after the IEND
of a valid 1x1 PNG (see `PNG_STUB` in `js/crypto.js`) and is sent as
`image/png`: the sniffer sees a real PNG, image decoders ignore the trailing
bytes, and because blobs are content-addressed a server that returns them
unchanged round-trips. Both defaults were verified to store the bytes verbatim,
including non-image payloads. A server that transcodes the "image" corrupts the
tail; the sha256 check on download catches it and the next mirror is tried.

Add your own Blossom instances to the server list for mirroring across more
jurisdictions.

## Crypto note

Web Crypto has no XChaCha20-Poly1305, so the content cipher is AES-256-GCM —
the native AEAD, and Firefox Send's actual choice. A fresh random content key
per file means the deterministic counter nonce never repeats. No WASM, no CDN.

The one third-party dependency is `vendor/nostr-tools.js` — a prebuilt ESM
bundle (nostr-tools + `@noble/curves`, MIT). It schnorr-signs the upload-auth
event and provides NIP-44 v2 + NIP-59 for gift-wrap delivery; nothing crypto is
hand-rolled, per `docs/ARCHITECTURE.md` §11. It is committed, so there is still
no build step. Regenerate it from `vendor/_entry.js` (rebuild command is in that
file) only when bumping nostr-tools.

## Run

```sh
node server/blossom-mock.js   # storage on :3000  (dev mock, no auth)
node server/static.js         # web on :8080
# open http://localhost:8080
```

Upload a file → copy the link → open it in another tab/browser to decrypt.

## Test

```sh
node test/crypto.test.mjs                                  # crypto unit tests
node test/nostr.test.mjs                                   # gift-wrap unit tests
PORT=3111 node server/blossom-mock.js &                    # then:
SERVER=http://localhost:3111 node test/e2e.test.mjs        # upload/download e2e
```

`crypto.test.mjs` covers round-trip, padding, wrong-key, bit-flip, truncation,
and header-tamper rejection. `nostr.test.mjs` covers gift-wrap round-trip,
sender hiding, unsigned-rumor deniability, recipient isolation, and key parsing
(offline). `e2e.test.mjs` covers encrypt → upload → download → hash-verify →
decrypt against a live Blossom server.

## Layout

```
index.html            HN-minimal UI
app.css               styles
js/crypto.js          encryption core (isomorphic: browser + Node 20+)
js/blossom.js         BUD-01/02 client
js/nostr-auth.js      throwaway-key BUD-02 upload auth
js/nostr-share.js     NIP-59 gift-wrap seal/unwrap + relay send/inbox
js/descriptor.js      link/fragment build + parse
js/app.js             DOM wiring
vendor/nostr-tools.js prebuilt nostr-tools bundle (schnorr + nip44/nip59, MIT)
vendor/_entry.js      bundle entry + rebuild command
server/blossom-mock.js  zero-dep content-addressed store (dev)
server/static.js        zero-dep static server (dev)
test/                 crypto + gift-wrap + e2e tests
docs/ARCHITECTURE.md  full threat model and design
```

## Security status

Unaudited. The construction is a composition of reviewed patterns (STREAM AEAD,
HKDF domain separation, fragment key delivery), but the composition itself has
not had an independent review. Do not use for real high-threat scenarios yet.

Content-key and plaintext byte buffers are zeroized after use (`wipe()` in
`js/crypto.js`), and **clear** (or closing the tab, via `pagehide`) scrubs the
link, nsec, recipient, and selected file from the tab. This is best-effort
residue reduction only: JS strings (the link, an nsec) are immutable and cannot
be wiped, the GC may have already copied a buffer, and the OS may page memory to
disk. The device-seizure defense the threat model asks for (duress vaults,
`docs/ARCHITECTURE.md` §4) is still unbuilt.
