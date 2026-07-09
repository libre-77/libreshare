// Run: node test/crypto.test.mjs
import {
  encryptBytes, encryptPart, decryptBytes, decryptToSink, decryptPartToSink,
  readMeta, randomBytes, paddedLength, wipe, newContentKey,
} from '../js/crypto.js';

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
  // Small files floor to the 64KiB bucket; above it the padding overhead is
  // bounded to <=12.5% (top-3-significant-bits rounding) and never shrinks.
  ok('tiny files floor to 64KiB', paddedLength(1) === 64 * 1024 && paddedLength(64 * 1024) === 64 * 1024);
  {
    const M = 1024 * 1024;
    const sizes = [300 * 1024, 700 * 1024, 9 * M, 33 * M, 65 * M, 100 * M, 4 * 1024 * M + 7];
    ok('padding never shrinks the file', sizes.every((n) => paddedLength(n) >= n));
    ok('padding overhead <= 12.5%', sizes.every((n) => paddedLength(n) <= n * 1.125 + 1));
    ok('33MiB no longer doubles to 64MiB', paddedLength(33 * M) === 36 * M);
  }
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

// 7. wipe() zeroizes a buffer and is a no-op on non-arrays
{
  const b = randomBytes(64);
  wipe(b);
  ok('wipe zeroes every byte', b.every((x) => x === 0));
  let threw = false;
  try { wipe(undefined); wipe('nope'); wipe(null); } catch { threw = true; }
  ok('wipe is a no-op on non-arrays', !threw);
}

// 8. encrypt still round-trips after internally scrubbing its plaintext buffer,
//    and does not corrupt the caller's input (only the internal padded copy).
{
  const plain = randomBytes(300 * 1024); // spans chunks + padding tail
  const snapshot = plain.slice();
  const { blob, ck, realSize } = await encryptBytes(plain, 'a', '');
  ok('caller plaintext untouched by internal wipe', eq(plain, snapshot));
  const out = await decryptBytes(blob, ck, realSize);
  ok('round trip intact after zeroize', eq(out, snapshot));
}

// 9. decryptToSink awaits an async sink before scrubbing, so a streamed
//    consumer still receives correct bytes (no wipe-before-write race).
{
  const plain = randomBytes(600 * 1024);
  const { blob, ck, realSize } = await encryptBytes(plain, 'a', '');
  const parts = [];
  await decryptToSink(blob, ck, realSize, async (p) => {
    await Promise.resolve();          // force the sink to be genuinely async
    parts.push(p.slice());            // copy as a real streaming sink would
  });
  let n = 0; for (const p of parts) n += p.length;
  const joined = new Uint8Array(n); let o = 0;
  for (const p of parts) { joined.set(p, o); o += p.length; }
  ok('async sink receives intact plaintext', eq(joined, plain));
}

// 10. multipart: split plaintext into parts (own subkeys), decrypt in order.
{
  const ck = newContentKey();
  const total = randomBytes(700 * 1024);
  const PART = 256 * 1024;
  const n = Math.ceil(total.length / PART);
  const parts = [];
  for (let i = 0; i < n; i++) {
    const slice = total.subarray(i * PART, Math.min((i + 1) * PART, total.length));
    parts.push(await encryptPart(slice, ck, i));
  }
  ok('split into >1 part', n > 1);

  // reassemble by decrypting each part under its index
  const out = [];
  for (let i = 0; i < n; i++) {
    await decryptPartToSink(parts[i].blob, ck, i, parts[i].realSize, (p) => out.push(p.slice()));
  }
  let len = 0; for (const p of out) len += p.length;
  const joined = new Uint8Array(len); let o = 0;
  for (const p of out) { joined.set(p, o); o += p.length; }
  ok('multipart round trip equals original', eq(joined, total));
}

// 11. distinct subkeys: identical plaintext in two parts -> different ciphertext
//     (proves no (key,nonce) reuse across parts).
{
  const ck = newContentKey();
  const same = randomBytes(200 * 1024);
  const a = await encryptPart(same, ck, 0);
  const b = await encryptPart(same, ck, 1);
  ok('same plaintext, different part -> different blob', !eq(a.blob, b.blob));
}

// 12. wrong part index fails auth (a part decrypted under the wrong subkey).
{
  const ck = newContentKey();
  const p1 = await encryptPart(randomBytes(50 * 1024), ck, 1);
  await throws('part decrypted under wrong index rejected', () =>
    decryptPartToSink(p1.blob, ck, 2, p1.realSize, () => {}));
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
