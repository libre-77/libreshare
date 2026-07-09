// Run: node test/crypto.test.mjs
import { encryptBytes, decryptBytes, decryptToSink, readMeta, randomBytes, paddedLength } from '../js/crypto.js';

let pass = 0, fail = 0;
function ok(name, cond) {
  if (cond) { pass++; console.log(`  ok  ${name}`); }
  else { fail++; console.log(`FAIL  ${name}`); }
}
async function throws(name, fn) {
  try { await fn(); fail++; console.log(`FAIL  ${name} (did not throw)`); }
  catch { pass++; console.log(`  ok  ${name}`); }
}
function eq(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// 1. round trip across chunk boundaries (700 KiB > 2 chunks of 256 KiB)
{
  const plain = randomBytes(700 * 1024);
  const { blob, blobHash, ck, realSize, meta } = await encryptBytes(plain, 'secret.pdf', 'application/pdf');
  ok('blobHash is hex64', /^[0-9a-f]{64}$/.test(blobHash));
  ok('padded larger than real', blob.length > realSize);
  ok('realSize preserved', realSize === plain.length);
  const out = await decryptBytes(blob, ck, realSize);
  ok('round trip bytes equal', eq(plain, out));
  const m = await readMeta(ck, meta);
  ok('meta name recovered', m.name === 'secret.pdf' && m.mime === 'application/pdf');
}

// 2. size padding hides exact length (empty file still padded)
{
  const { blob, realSize } = await encryptBytes(new Uint8Array(0), 'x', '');
  ok('empty padded to 64KiB bucket', blob.length >= 64 * 1024);
  ok('empty realSize is 0', realSize === 0);
  ok('paddedLength ladder', paddedLength(1) === 64 * 1024 && paddedLength(300 * 1024) === 512 * 1024);
}

// 3. wrong key fails
{
  const plain = randomBytes(100 * 1024);
  const { blob, realSize } = await encryptBytes(plain, 'a', '');
  await throws('wrong key rejected', () => decryptBytes(blob, randomBytes(32), realSize));
}

// 4. single-bit tamper fails (GCM auth)
{
  const plain = randomBytes(100 * 1024);
  const { blob, ck, realSize } = await encryptBytes(plain, 'a', '');
  const t = blob.slice();
  t[t.length - 1] ^= 0x01;
  await throws('bit flip rejected', () => decryptBytes(t, ck, realSize));
}

// 5. truncation attack: drop the final chunk. The new last chunk was sealed
//    with final=0 but the decryptor verifies it as final=1 -> auth fail.
{
  const plain = randomBytes(700 * 1024); // 3 chunks
  const { blob, ck, realSize } = await encryptBytes(plain, 'a', '');
  const encChunk = 256 * 1024 + 16;
  const truncated = blob.subarray(0, blob.length - encChunk);
  await throws('truncation rejected', () =>
    decryptToSink(truncated, ck, realSize, () => {}));
}

// 6. header magic tamper fails
{
  const plain = randomBytes(50 * 1024);
  const { blob, ck, realSize } = await encryptBytes(plain, 'a', '');
  const t = blob.slice();
  t[0] ^= 0xff;
  await throws('bad magic rejected', () => decryptBytes(t, ck, realSize));
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
