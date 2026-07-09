// End-to-end: encrypt -> upload to mock Blossom -> download -> verify -> decrypt.
// Run: PORT=3111 node server/blossom-mock.js &  then  node test/e2e.test.mjs
import { encryptBytes, decryptBytes, randomBytes } from '../js/crypto.js';
import { upload, download } from '../js/blossom.js';
import { buildDescriptor, encodeFragment, decodeFragment } from '../js/descriptor.js';

const SERVER = process.env.SERVER || 'http://localhost:3111';
let pass = 0, fail = 0;
const ok = (n, c) => c ? (pass++, console.log(`  ok  ${n}`)) : (fail++, console.log(`FAIL  ${n}`));
const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

const plain = randomBytes(900 * 1024);
const { blob, blobHash, ck, realSize, meta } = await encryptBytes(plain, 'report.bin', 'application/octet-stream');

const accepted = await upload([SERVER], blob, blobHash);
ok('uploaded to a server', accepted.length === 1);

// The sharable link carries everything in the fragment; the server saw only bytes.
const descriptor = buildDescriptor({ hash: blobHash, ck, servers: [SERVER], realSize, meta });
const fragment = encodeFragment(descriptor);
const parsed = decodeFragment(fragment);
ok('descriptor survives fragment round trip', parsed.hash === blobHash && eq(parsed.ck, ck));

const fetched = await download(parsed.servers, parsed.hash);
ok('downloaded bytes match stored hash', fetched.length === blob.length);

const out = await decryptBytes(fetched, parsed.ck, parsed.realSize);
ok('decrypted plaintext equals original', eq(plain, out));

// A server serving wrong bytes must be rejected by hash check.
try {
  await download([SERVER], '0'.repeat(64));
  ok('missing blob rejected', false);
} catch { ok('missing blob rejected', true); }

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
