// Bundle entry for vendor/nostr-tools.js. Re-exports exactly what the app uses:
// schnorr signing (BUD-02 upload auth), plus NIP-44 v2 + NIP-59 gift wrap and
// NIP-19 key encoding for the Nostr share/inbox flow. Rebuild with:
//   npm install --no-save nostr-tools@2.23.9 esbuild
//   node_modules/.bin/esbuild vendor/_entry.js --bundle --format=esm \
//     --minify --outfile=vendor/nostr-tools.js
export {
  finalizeEvent,
  generateSecretKey,
  getPublicKey,
  verifyEvent,
} from 'nostr-tools/pure';
export { SimplePool } from 'nostr-tools/pool';
export * as nip19 from 'nostr-tools/nip19';
export * as nip44 from 'nostr-tools/nip44';
export * as nip59 from 'nostr-tools/nip59';
