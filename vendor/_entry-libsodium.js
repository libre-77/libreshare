// Bundle entry for vendor/libsodium.js. Rebuild with:
//   npm install --no-save libsodium-wrappers@0.8.4 esbuild
//   node_modules/.bin/esbuild vendor/_entry-libsodium.js --bundle --format=esm \
//     --minify --outfile=vendor/libsodium.js
export { default } from 'libsodium-wrappers';
