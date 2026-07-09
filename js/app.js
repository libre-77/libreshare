import { encryptBytes, decryptToSink, readMeta } from './crypto.js';
import { upload, download } from './blossom.js';
import { buildDescriptor, buildLink, decodeFragment } from './descriptor.js';
import { wrapLink, publishWrap, fetchWraps, generateIdentity } from './nostr-share.js';
import { initI18n, setLang, getLang, t, humanSize } from './i18n.js';

const $ = (id) => document.getElementById(id);
const show = (id, on = true) => { $(id).hidden = !on; };
const SECTIONS = ['upload', 'download', 'about', 'inbox'];
const showOnly = (id) => SECTIONS.forEach((s) => show(s, s === id));
const csv = (v) => v.split(',').map((s) => s.trim()).filter(Boolean);

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
    const bytes = new Uint8Array(await file.arrayBuffer());

    prog.textContent = t('status.encrypting');
    const { blob, blobHash, ck, realSize, meta } =
      await encryptBytes(bytes, file.name, file.type || 'application/octet-stream',
        (p) => { prog.textContent = t('status.encryptingPct', { pct: Math.round(p * 100) }); });

    prog.textContent = t('status.uploading');
    const accepted = await upload(servers, blob, blobHash);

    const descriptor = buildDescriptor({ hash: blobHash, ck, servers: accepted, realSize, meta });
    $('link').value = buildLink(location.origin, descriptor);
    prog.textContent = t('status.stored', { count: accepted.length, size: humanSize(blob.length) });
    show('up-result', true);
  } catch (err) {
    prog.textContent = t('error.generic', { msg: err.message });
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
    const meta = await readMeta(d.ck, d.meta);
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
    const blob = await download(d.servers, d.hash);

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
      (p) => { prog.textContent = t('status.decryptingPct', { pct: Math.round(p * 100) }); });
    await finish();
    prog.textContent = t('status.saved');
  } catch (err) {
    show('dl-error', true);
    $('dl-error').textContent = t('error.downloadFailed', { msg: err.message });
    prog.textContent = '';
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

// ---- Nav ----

$('nav-inbox').addEventListener('click', (e) => { e.preventDefault(); showOnly('inbox'); });
$('nav-about').addEventListener('click', (e) => { e.preventDefault(); showOnly('about'); });

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
