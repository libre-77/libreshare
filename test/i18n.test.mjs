// i18n: dictionaries stay in lockstep, and every key the markup asks for exists.
// Run: node test/i18n.test.mjs
import { readFileSync } from 'node:fs';
import { STRINGS, SUPPORTED, DEFAULT_LANG, t, humanSize } from '../js/i18n.js';

let pass = 0, fail = 0;
const ok = (n, c) => c ? (pass++, console.log(`  ok  ${n}`)) : (fail++, console.log(`FAIL  ${n}`));

const placeholders = (s) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort().join(',');

const baseKeys = Object.keys(STRINGS[DEFAULT_LANG]).sort();
ok('every supported language has a dictionary', SUPPORTED.every((l) => STRINGS[l]));

for (const lang of SUPPORTED) {
  if (lang === DEFAULT_LANG) continue;
  const keys = Object.keys(STRINGS[lang]).sort();
  ok(`${lang} has exactly the ${DEFAULT_LANG} keys`, keys.join('|') === baseKeys.join('|'));

  const mismatched = baseKeys.filter(
    (k) => placeholders(STRINGS[lang][k] ?? '') !== placeholders(STRINGS[DEFAULT_LANG][k]));
  ok(`${lang} preserves every {placeholder}`, mismatched.length === 0);
  if (mismatched.length) console.log(`      ${mismatched.join(', ')}`);
}

// The markup drives translation via data-i18n*, so a typo there silently ships
// the raw key to users. Catch it here instead.
const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
const used = [...html.matchAll(/data-i18n(?:-placeholder|-title)?="([^"]+)"/g)].map((m) => m[1]);
ok('index.html declares at least one key', used.length > 0);
const missing = used.filter((k) => !(k in STRINGS[DEFAULT_LANG]));
ok('every data-i18n key exists in the dictionary', missing.length === 0);
if (missing.length) console.log(`      ${missing.join(', ')}`);

ok('t() substitutes placeholders', t('status.stored', { count: 2, size: '1.0 KB' }) === 'stored on 2 server(s), 1.0 KB ciphertext');
ok('t() falls back to the key when unknown', t('nope.nope') === 'nope.nope');
ok('t() leaves unmatched placeholders alone', t('error.generic') === 'error: {msg}');

ok('humanSize formats bytes', humanSize(512) === '512 B');
ok('humanSize formats KB', humanSize(1536) === '1.5 KB');
ok('humanSize formats MB', humanSize(5 * 1024 * 1024) === '5.0 MB');
ok('humanSize caps at GB', humanSize(3 * 1024 ** 4) === '3072 GB');

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
