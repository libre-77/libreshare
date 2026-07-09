import { encryptBytes, decryptToSink, readMeta, wipe } from './crypto.js';
import { upload, download, DEFAULT_SERVERS } from './blossom.js';
import { buildDescriptor, buildLink, decodeFragment } from './descriptor.js';
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
}

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
  show('up-result', false);
  show('up-progress', true);
  const prog = $('up-progress');

  try {
    prog.textContent = t('status.reading');
    setBar('up-bar', 0);
    const bytes = new Uint8Array(await file.arrayBuffer());

    // Encryption fills the first half of the bar, upload the second half.
    prog.textContent = t('status.encrypting');
    const { blob, blobHash, ck, realSize, meta } =
      await encryptBytes(bytes, file.name, file.type || 'application/octet-stream',
        (p) => {
          prog.textContent = t('status.encryptingPct', { pct: Math.round(p * 100) });
          setBar('up-bar', p * 50);
        });

    prog.textContent = t('status.uploading');
    const accepted = await upload(servers, blob, blobHash, undefined, (p) => {
      setBar('up-bar', 50 + p * 50);
      // p reaches 1 when every byte is sent, but upload() only resolves once the
      // servers respond (write + hash + round trip) — so show a distinct state
      // instead of a bar that sits at 100% looking stuck.
      prog.textContent = p >= 1 ? t('status.confirming') : t('status.uploadingPct', { pct: Math.round(p * 100) });
    });
    setBar('up-bar', 100);

    // With "embed servers" off (default), the link omits its server list to
    // stay short and is resolved against DEFAULT_SERVERS on download — so it
    // only opens on apps that share those defaults. On = self-contained link
    // carrying its own mirrors, longer but portable to any instance.
    const embed = $('embed-servers').checked;
    // Filename/mime (meta) is optional too: omit it for a shorter link and the
    // recipient just sees a generic name. It is already encrypted either way —
    // no server ever sees it; this only controls what the link itself carries.
    const embedMeta = $('embed-meta').checked;
    const descriptor = buildDescriptor({
      hash: blobHash, ck, servers: embed ? accepted : [], realSize,
      meta: embedMeta ? meta : new Uint8Array(0),
    });
    $('link').value = buildLink(location.origin, descriptor);
    prog.textContent = t('status.stored', { count: accepted.length, size: humanSize(blob.length) });
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
  $('d-hash').textContent = d.hash;
}

$('download-btn').addEventListener('click', async () => {
  if (!current) return;
  const { d, meta } = current;
  $('download-btn').disabled = true;
  show('dl-error', false);
  show('dl-progress', true);
  const prog = $('dl-progress');

  try {
    prog.textContent = t('status.downloading');
    setBar('dl-bar', null); // indeterminate: GET progress isn't tracked
    // A link may omit its servers (short mode); fall back to the app defaults.
    const servers = d.servers.length ? d.servers : DEFAULT_SERVERS;
    const blob = await download(servers, d.hash);

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

    prog.textContent = t('status.decrypting');
    await decryptToSink(blob, d.ck, d.realSize, sink,
      (p) => {
        prog.textContent = t('status.decryptingPct', { pct: Math.round(p * 100) });
        setBar('dl-bar', p * 100);
      });
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

window.addEventListener('hashchange', route);
route();
