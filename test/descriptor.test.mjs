// Run: node test/descriptor.test.mjs
// Binary descriptor: round trip, length win, edge sizes, and legacy v1 compat.
import {
  buildDescriptor, buildMultipartDescriptor, encodeFragment, decodeFragment, buildLink,
  b64urlEncode, b64urlDecode,
} from '../js/descriptor.js';

let pass = 0, fail = 0;
const ok = (n, c) => c ? (pass++, console.log(`  ok  ${n}`)) : (fail++, console.log(`FAIL  ${n}`));
const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

const hash = '41cac542ebeb4136231e754c9c232a98f791e58a2f276b13599258c41df85897';
const ck = Uint8Array.from({ length: 32 }, (_, i) => (i * 7 + 3) & 0xff);
const meta = Uint8Array.from({ length: 83 }, (_, i) => (i * 5 + 1) & 0xff);
const servers = ['https://blossom.band', 'https://blossom.nostr.build'];

// 1. round trip: every field survives encode -> decode
{
  const d = buildDescriptor({ hash, ck, servers, realSize: 30, meta });
  const frag = encodeFragment(d);
  const p = decodeFragment(frag);
  ok('hash preserved', p.hash === hash);
  ok('ck preserved', eq(p.ck, ck));
  ok('meta preserved', eq(p.meta, meta));
  ok('servers preserved', p.servers.length === 2 && p.servers[0] === servers[0] && p.servers[1] === servers[1]);
  ok('realSize preserved', p.realSize === 30);
  ok('version is 4 (current: libsodium content/meta)', p.v === 4);
}

// 2. it is actually shorter than the old JSON form
{
  const d = buildDescriptor({ hash, ck, servers, realSize: 30, meta });
  const frag = encodeFragment(d);
  const jsonFrag = b64urlEncode(new TextEncoder().encode(JSON.stringify({
    v: 1, hash, ck: b64urlEncode(ck), servers, realSize: 30, meta: b64urlEncode(meta),
  })));
  ok(`binary (${frag.length}) shorter than json (${jsonFrag.length})`, frag.length < jsonFrag.length);
  ok('binary is <300 chars for this case', frag.length < 300);
}

// 3. large realSize past 2^32 stays exact (varint arithmetic, not 32-bit ops)
{
  const big = 5 * 1024 * 1024 * 1024 + 123; // ~5 GiB
  const d = buildDescriptor({ hash, ck, servers: [], realSize: big, meta: new Uint8Array(0) });
  const p = decodeFragment(encodeFragment(d));
  ok('realSize > 4 GiB round trips', p.realSize === big);
  ok('empty servers + empty meta round trips', p.servers.length === 0 && p.meta.length === 0);
}

// 4. buildLink puts it after the fragment
{
  const d = buildDescriptor({ hash, ck, servers, realSize: 1, meta });
  const link = buildLink('https://app.example', d);
  ok('link has fragment', link.startsWith('https://app.example/#'));
  ok('decoding the fragment recovers ck', eq(decodeFragment(link.split('#')[1]).ck, ck));
}

// 5. legacy v1 (base64url JSON) still decodes
{
  const v1 = b64urlEncode(new TextEncoder().encode(JSON.stringify({
    v: 1, hash, ck: b64urlEncode(ck), servers, realSize: 30, meta: b64urlEncode(meta),
  })));
  const p = decodeFragment(v1);
  ok('v1 hash decodes', p.hash === hash);
  ok('v1 ck decodes', eq(p.ck, ck));
  ok('v1 meta decodes', eq(p.meta, meta));
}

// 6. junk / unknown version is rejected, not silently mis-parsed
{
  const junk = b64urlEncode(Uint8Array.from([0x09, 1, 2, 3]));
  let threw = false;
  try { decodeFragment(junk); } catch { threw = true; }
  ok('unknown version rejected', threw);
}

// 7. multipart (v3): ordered part list + per-part sizes survive round trip
{
  const parts = [
    { hash: 'a'.repeat(64), realSize: 8 * 1024 * 1024 },
    { hash: 'b'.repeat(64), realSize: 8 * 1024 * 1024 },
    { hash: 'c'.repeat(64), realSize: 1234 },
  ];
  const d = buildMultipartDescriptor({ ck, parts, servers, realSize: 16 * 1024 * 1024 + 1234, meta });
  const p = decodeFragment(encodeFragment(d));
  ok('v5 version (current multipart: libsodium content/meta)', p.v === 5);
  ok('v3 ck preserved', eq(p.ck, ck));
  ok('v3 part count', p.parts.length === 3);
  ok('v3 part order + hashes', p.parts.map((x) => x.hash).join(',') === parts.map((x) => x.hash).join(','));
  ok('v3 per-part sizes', p.parts[2].realSize === 1234);
  ok('v3 total realSize', p.realSize === 16 * 1024 * 1024 + 1234);
  ok('v3 servers + meta', p.servers.length === 2 && eq(p.meta, meta));
}

// 8. multipart with meta and servers omitted (shortest multipart link)
{
  const parts = [{ hash: 'd'.repeat(64), realSize: 100 }, { hash: 'e'.repeat(64), realSize: 50 }];
  const d = buildMultipartDescriptor({ ck, parts, servers: [], realSize: 150, meta: new Uint8Array(0) });
  const p = decodeFragment(encodeFragment(d));
  ok('v3 empty servers + meta round trips', p.servers.length === 0 && p.meta.length === 0 && p.parts.length === 2);
}

// 9. legacy raw v2 (pre-libsodium, AES-GCM content/meta) descriptor still
//    decodes at the layout level — a link shared before this change must keep
//    resolving. v2 and v4 share byte layout exactly (see descriptor.js), so
//    building a v4 fragment and flipping just the leading version byte to 2
//    produces exactly what a pre-libsodium upload would have emitted.
{
  const d = buildDescriptor({ hash, ck, servers, realSize: 30, meta });
  const frag = encodeFragment(d);
  const bytes = b64urlDecode(frag);
  bytes[0] = 2; // VERSION (legacy) in place of VERSION_SODIUM (4)
  const p = decodeFragment(b64urlEncode(bytes));
  ok('legacy v2 (raw bytes) still decodes', p.v === 2 && p.hash === hash && eq(p.ck, ck) && eq(p.meta, meta));
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
