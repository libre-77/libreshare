import {
  encryptBytes, encryptPart, encryptMetaField, newContentKey,
  decryptToSink, decryptPartToSink, readMeta, wipe,
} from './crypto.js';
import { upload, download, detectMaxBlob, DEFAULT_SERVERS } from './blossom.js';
import { buildDescriptor, buildMultipartDescriptor, buildLink, decodeFragment } from './descriptor.js';
import { wrapLink, publishWrap, fetchWraps, generateIdentity } from './nostr-share.js';
import { initI18n, setLang, getLang, t, humanSize } from './i18n.js';

const $ = (id) => document.getElementById(id);
const show = (id, on = true) => { $(id).hidden = !on; };
const SECTIONS = ['upload', 'download', 'about', 'inbox'];
const showOnly = (id) => SECTIONS.forEach((s) => show(s, s === id));
const csv = (v) => v.split(',').map((s) => s.trim()).filter(Boolean);

// Drive a <progress> bar. pct null -> indeterminate (drop the value attribute);
// a number -> determinate 0..100. Pass on:false to hide it.
function setBar(id, pct, on = true) {
  const b = $(id);
  if (!b) return;
  if (pct == null) b.removeAttribute('value');
  else b.value = Math.max(0, Math.min(100, pct));
  b.hidden = !on;
  // The upload bar is mirrored into the floating widget so progress stays
  // visible after the user navigates away from the upload section.
  if (id === 'up-bar') {
    const f = $('up-float-bar');
    if (f) {
      if (pct == null) f.removeAttribute('value');
      else f.value = Math.max(0, Math.min(100, pct));
    }
  }
}

// True while an upload is in flight; keeps the floating progress pinned even if
// the user clicks away to inbox/about (nav only toggles <main>'s sections).
let uploading = false;

initI18n();

function route() {
  const frag = location.hash.slice(1);
  if (frag.length > 0) { showOnly('download'); renderDownload(frag); }
  else { showOnly('upload'); }
}

// ---- Upload ----

$('upload-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const file = $('file').files[0];
  if (!file) return;
  const servers = $('servers').value.split(',').map((s) => s.trim()).filter(Boolean);
  if (servers.length === 0) return;

  $('go').disabled = true;
  uploading = true;
  show('up-result', false);
  show('up-progress', true);
  show('up-float', true);
  // Write status text to both the in-section line and the floating widget.
  const progEl = $('up-progress');
  const floatText = $('up-float-text');
  const prog = { set textContent(v) { progEl.textContent = v; floatText.textContent = v; } };

  try {
    // Part size: a blank field auto-detects each server's blob cap (BUD-06 HEAD)
    // and leaves headroom for padding+overhead; a number is a manual MB override.
    // Cap parts at 100 MiB so a permissive server doesn't force a huge in-memory
    // blob.
    const HARD_CAP = 100 * 1024 * 1024;
    const manualMB = parseFloat($('max-part').value);
    let maxPartBytes;
    if (manualMB > 0) {
      maxPartBytes = Math.max(64 * 1024, Math.floor(manualMB * 1024 * 1024));
    } else {
      prog.textContent = t('status.detecting');
      const limit = await detectMaxBlob(servers);
      // limit is the max blob; leave ~15% for padding (<=12.5%) + stub/tags.
      maxPartBytes = limit ? Math.floor(limit / 1.15) : 16 * 1024 * 1024;
      maxPartBytes = Math.max(64 * 1024, Math.min(maxPartBytes, HARD_CAP));
    }

    prog.textContent = t('status.reading');
    setBar('up-bar', 0);
    const bytes = new Uint8Array(await file.arrayBuffer());
    const name = file.name;
    const mime = file.type || 'application/octet-stream';

    // Toggles: whether the link carries its own server list / filename.
    const embed = $('embed-servers').checked;
    const embedMeta = $('embed-meta').checked;

    let descriptor;
    let ck; let meta; let storedCount;
    if (bytes.length <= maxPartBytes) {
      // Single blob (part 0) — encrypt fills the first half of the bar, upload
      // the second.
      prog.textContent = t('status.encrypting');
      const enc = await encryptBytes(bytes, name, mime, (p) => {
        prog.textContent = t('status.encryptingPct', { pct: Math.round(p * 100) });
        setBar('up-bar', p * 50);
      });
      ck = enc.ck; meta = enc.meta;
      prog.textContent = t('status.uploading');
      const accepted = await upload(servers, enc.blob, enc.blobHash, undefined, (p) => {
        setBar('up-bar', 50 + p * 50);
        prog.textContent = p >= 1 ? t('status.confirming') : t('status.uploadingPct', { pct: Math.round(p * 100) });
      });
      storedCount = accepted.length;
      descriptor = buildDescriptor({
        hash: enc.blobHash, ck, servers: embed ? accepted : [], realSize: enc.realSize,
        meta: embedMeta ? meta : new Uint8Array(0),
      });
    } else {
      // Multipart: split the plaintext, encrypt+upload each part in turn (each
      // under its own subkey), and record the ordered part hashes. A server is
      // kept only if it accepted every part, so any listed server has the whole
      // file.
      ck = newContentKey();
      const n = Math.ceil(bytes.length / maxPartBytes);
      const parts = [];
      let acceptedAll = null;
      for (let i = 0; i < n; i++) {
        const slice = bytes.subarray(i * maxPartBytes, Math.min((i + 1) * maxPartBytes, bytes.length));
        prog.textContent = t('status.encryptingPart', { i: i + 1, n });
        const pt = await encryptPart(slice, ck, i, (p) => setBar('up-bar', ((i + p * 0.5) / n) * 100));
        prog.textContent = t('status.uploadingPart', { i: i + 1, n });
        const acc = await upload(servers, pt.blob, pt.blobHash, undefined,
          (p) => setBar('up-bar', ((i + 0.5 + p * 0.5) / n) * 100));
        acceptedAll = acceptedAll ? acceptedAll.filter((s) => acc.includes(s)) : acc;
        parts.push({ hash: pt.blobHash, realSize: pt.realSize });
        wipe(pt.blob);
      }
      if (!acceptedAll || acceptedAll.length === 0) throw new Error(t('error.partServers'));
      meta = await encryptMetaField(ck, name, mime);
      storedCount = acceptedAll.length;
      descriptor = buildMultipartDescriptor({
        ck, parts, servers: embed ? acceptedAll : [], realSize: bytes.length,
        meta: embedMeta ? meta : new Uint8Array(0),
      });
      prog.textContent = t('status.storedParts', { parts: n, count: storedCount });
    }

    setBar('up-bar', 100);
    $('link').value = buildLink(location.origin, descriptor);
    if (bytes.length <= maxPartBytes) {
      prog.textContent = t('status.stored', { count: storedCount, size: humanSize(bytes.length) });
    }
    setBar('up-bar', 100, false);
    show('up-result', true);

    // The link now carries base64url copies of the key and meta; scrub the raw
    // byte buffers so the plaintext file and key don't linger on the heap. The
    // link string itself is what the user needs and cannot be wiped — clear it
    // with the "clear" action (or on tab exit) once it has been shared.
    wipe(ck); wipe(meta); wipe(bytes);
  } catch (err) {
    prog.textContent = t('error.generic', { msg: err.message });
    setBar('up-bar', null, false);
  } finally {
    $('go').disabled = false;
    uploading = false;
  }
});

$('copy').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('link').value); }
  catch { $('link').select(); document.execCommand('copy'); }
  show('copied', true);
  setTimeout(() => show('copied', false), 1500);
});

// ---- Download ----

let current = null;

async function renderDownload(frag) {
  show('dl-error', false);
  show('dl-progress', false);
  try {
    const d = decodeFragment(frag);
    // A link may omit meta (shorter mode); fall back to a generic name/type.
    const meta = d.meta.length ? await readMeta(d.ck, d.meta) : { name: null, mime: null };
    current = { d, meta };
    renderDownloadMeta();
    $('download-btn').disabled = false;
  } catch (err) {
    current = null;
    $('d-name').textContent = '—';
    $('d-hash').textContent = '—';
    $('download-btn').disabled = true;
    show('dl-error', true);
    $('dl-error').textContent = t('error.badLink', { msg: err.message });
  }
}

function renderDownloadMeta() {
  if (!current) return;
  const { d, meta } = current;
  $('d-name').textContent = meta.name || t('download.unnamed');
  $('d-mime').textContent = meta.mime || 'application/octet-stream';
  $('d-size').textContent = humanSize(d.realSize);
  $('d-hash').textContent = d.v === 3 ? t('download.parts', { n: d.parts.length }) : d.hash;
}

$('download-btn').addEventListener('click', async () => {
  if (!current) return;
  const { d, meta } = current;
  $('download-btn').disabled = true;
  show('dl-error', false);
  show('dl-progress', true);
  const prog = $('dl-progress');

  try {
    // A link may omit its servers (short mode); fall back to the app defaults.
    const servers = d.servers.length ? d.servers : DEFAULT_SERVERS;

    // Prefer streaming straight to disk; fall back to an in-memory Blob.
    let sink, finish;
    if (window.showSaveFilePicker) {
      const handle = await window.showSaveFilePicker({ suggestedName: meta.name || 'file' });
      const writable = await handle.createWritable();
      sink = (chunk) => writable.write(chunk);
      finish = () => writable.close();
    } else {
      const parts = [];
      sink = (chunk) => parts.push(chunk.slice());
      finish = () => {
        const url = URL.createObjectURL(new Blob(parts, { type: meta.mime || 'application/octet-stream' }));
        const a = document.createElement('a');
        a.href = url; a.download = meta.name || 'file';
        a.click();
        URL.revokeObjectURL(url);
      };
    }

    if (d.v === 3) {
      // Multipart: fetch each part in order, decrypt it under its own subkey,
      // and stream straight into the same sink so nothing is buffered whole.
      const n = d.parts.length;
      for (let i = 0; i < n; i++) {
        prog.textContent = t('status.downloadingPart', { i: i + 1, n });
        setBar('dl-bar', (i / n) * 100);
        const blob = await download(servers, d.parts[i].hash);
        await decryptPartToSink(blob, d.ck, i, d.parts[i].realSize, sink,
          (p) => setBar('dl-bar', ((i + p) / n) * 100));
      }
    } else {
      prog.textContent = t('status.downloading');
      setBar('dl-bar', null); // indeterminate: GET progress isn't tracked
      const blob = await download(servers, d.hash);
      prog.textContent = t('status.decrypting');
      await decryptToSink(blob, d.ck, d.realSize, sink,
        (p) => {
          prog.textContent = t('status.decryptingPct', { pct: Math.round(p * 100) });
          setBar('dl-bar', p * 100);
        });
    }
    await finish();
    prog.textContent = t('status.saved');
    setBar('dl-bar', 100, false);
  } catch (err) {
    show('dl-error', true);
    $('dl-error').textContent = t('error.downloadFailed', { msg: err.message });
    prog.textContent = '';
    setBar('dl-bar', null, false);
    $('download-btn').disabled = false;
  }
});

// ---- Nostr send (seal the just-built link into a gift wrap) ----

$('send-nostr').addEventListener('click', async () => {
  const link = $('link').value;
  const recip = $('recip').value.trim();
  const relays = csv($('send-relays').value);
  const sender = $('sender').value.trim() || undefined;

  show('send-error', false);
  show('send-status', false);
  if (!link) return;
  if (!recip) { show('send-error', true); $('send-error').textContent = t('error.needRecipient'); return; }
  if (relays.length === 0) { show('send-error', true); $('send-error').textContent = t('error.needRelay'); return; }

  $('send-nostr').disabled = true;
  try {
    const wrap = wrapLink(link, recip, sender);
    const accepted = await publishWrap(relays, wrap);
    show('send-status', true);
    $('send-status').textContent = t('status.sent', { count: accepted.length });
  } catch (err) {
    show('send-error', true);
    $('send-error').textContent = t('error.sendFailed', { msg: err.message });
  } finally {
    $('send-nostr').disabled = false;
  }
});

// ---- Inbox (fetch + unwrap gift wraps addressed to me) ----

let lastIdentity = null;
let lastItems = null;

function renderIdentity() {
  if (!lastIdentity) return;
  show('gen-id-out', true);
  $('gen-id-out').innerHTML = `<p>${t('inbox.genIdNote')}</p>`;
  const npub = document.createElement('textarea');
  npub.readOnly = true; npub.rows = 2; npub.value = lastIdentity.npub;
  $('gen-id-out').appendChild(npub);
}

$('check-inbox').addEventListener('click', async () => {
  const nsec = $('my-nsec').value.trim();
  const relays = csv($('inbox-relays').value);
  show('inbox-error', false);
  $('inbox-list').innerHTML = '';
  if (!nsec) { show('inbox-error', true); $('inbox-error').textContent = t('error.needNsec'); return; }
  if (relays.length === 0) { show('inbox-error', true); $('inbox-error').textContent = t('error.needRelay'); return; }

  $('check-inbox').disabled = true;
  show('inbox-progress', true);
  $('inbox-progress').textContent = t('inbox.querying');
  try {
    const items = await fetchWraps(relays, nsec);
    show('inbox-progress', false);
    lastItems = items;
    renderInbox(items);
  } catch (err) {
    show('inbox-progress', false);
    show('inbox-error', true);
    $('inbox-error').textContent = t('error.inboxFailed', { msg: err.message });
  } finally {
    $('check-inbox').disabled = false;
  }
});

function renderInbox(items) {
  const ul = $('inbox-list');
  ul.innerHTML = '';
  if (items.length === 0) {
    const li = document.createElement('li');
    const empty = document.createElement('span');
    empty.className = 'empty';
    empty.textContent = t('inbox.empty');
    li.appendChild(empty);
    ul.appendChild(li);
    return;
  }
  for (const it of items) {
    const li = document.createElement('li');
    const open = document.createElement('button');
    open.type = 'button';
    open.textContent = t('inbox.open');
    open.addEventListener('click', () => {
      const hash = it.link.includes('#') ? it.link.slice(it.link.indexOf('#') + 1) : '';
      if (!hash) { show('inbox-error', true); $('inbox-error').textContent = t('error.noFragment'); return; }
      location.hash = hash; // triggers route() -> download view
    });
    const from = document.createElement('span');
    from.className = 'from';
    from.textContent = t('inbox.from', { npub: it.npub.slice(0, 16) });
    li.appendChild(open);
    li.appendChild(document.createTextNode(t('inbox.sharedFile')));
    li.appendChild(from);
    ul.appendChild(li);
  }
}

// ---- Clear sensitive state (residue reduction) ----

// Wipe every place a key, link, or plaintext can linger: the byte buffers we
// still hold, the DOM fields showing the link / nsec / recipient, the selected
// file, and the in-memory references. This is best-effort — strings (the link,
// an nsec) are immutable and cannot be scrubbed from memory, and the OS may have
// paged memory to disk — but it removes the obvious residue and is the exit
// point the user (or tab-close) triggers.
function clearSensitive() {
  if (current?.d?.ck) wipe(current.d.ck);
  current = null;
  lastIdentity = null;
  lastItems = null;

  for (const id of ['link', 'recip', 'sender', 'my-nsec', 'file']) {
    const el = $(id);
    if (el) el.value = '';
  }
  $('gen-id-out').innerHTML = '';
  $('inbox-list').innerHTML = '';
  show('gen-id-out', false);
  show('up-result', false);
  show('send-status', false);
  show('send-error', false);
  setBar('up-bar', null, false);
  setBar('dl-bar', null, false);
  $('up-progress').textContent = '';
  show('up-float', false);
}

// ---- Nav ----

$('nav-inbox').addEventListener('click', (e) => { e.preventDefault(); showOnly('inbox'); });
$('nav-about').addEventListener('click', (e) => { e.preventDefault(); showOnly('about'); });
$('nav-clear').addEventListener('click', (e) => {
  e.preventDefault();
  clearSensitive();
  showOnly('upload');
  $('up-progress').textContent = t('status.cleared');
  show('up-progress', true);
});

// Clicking the floating progress jumps back to the upload section (revealing
// the in-progress bar or the finished link). Once the upload has finished, the
// click also dismisses the widget; while still running it stays pinned.
$('up-float').addEventListener('click', () => {
  showOnly('upload');
  if (!uploading) show('up-float', false);
});

// Guard an accidental reload/close mid-upload: the browser shows its own
// generic "leave site?" confirm (the text can't be customized). Only armed
// while an upload is in flight, so normal navigation is never nagged.
window.addEventListener('beforeunload', (e) => {
  if (!uploading) return;
  e.preventDefault();
  e.returnValue = '';
});

// Scrub on tab close / navigation away (also covers bfcache freeze).
window.addEventListener('pagehide', clearSensitive);

// #gen-id and #about-inbox live inside translated markup, so applyI18n()
// replaces those nodes on every language switch. Delegate instead of binding.
document.addEventListener('click', (e) => {
  const target = e.target.closest?.('#gen-id, #about-inbox, .lang-pick');
  if (!target) return;
  e.preventDefault();

  if (target.id === 'about-inbox') { showOnly('inbox'); return; }
  if (target.id === 'gen-id') {
    lastIdentity = generateIdentity();
    $('my-nsec').value = lastIdentity.nsec;
    renderIdentity();
    return;
  }
  switchLang(target.dataset.lang);
});

// ---- Language ----

function markActiveLang() {
  for (const a of document.querySelectorAll('.lang-pick')) {
    a.classList.toggle('active', a.dataset.lang === getLang());
  }
}

function switchLang(next) {
  if (next === getLang()) return;
  setLang(next);           // persists + re-applies static strings
  refreshDynamic();
}

/** Re-render everything JS built imperatively; applyI18n only covers markup. */
function refreshDynamic() {
  markActiveLang();
  renderDownloadMeta();
  if (lastIdentity) renderIdentity();
  if (lastItems) renderInbox(lastItems);
}

markActiveLang();

// ---- Persisted toggles ----
// Remember the two link-shape checkboxes across sessions. Keys are namespaced
// like i18n's `ls.lang`. Wrapped in try/catch — localStorage throws in some
// private-browsing modes. A missing key leaves the HTML default untouched, so
// a first visit still gets embed-servers off / embed-meta on.
const TOGGLES = { 'embed-servers': 'ls.embedServers', 'embed-meta': 'ls.embedMeta' };

for (const [id, key] of Object.entries(TOGGLES)) {
  let v = null;
  try { v = localStorage.getItem(key); } catch { /* private mode */ }
  if (v !== null) $(id).checked = v === '1';
  $(id).addEventListener('change', () => {
    try { localStorage.setItem(key, $(id).checked ? '1' : '0'); } catch { /* private mode */ }
  });
}

window.addEventListener('hashchange', route);
route();
