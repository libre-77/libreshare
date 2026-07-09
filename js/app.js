import { encryptBytes, decryptToSink, readMeta } from './crypto.js';
import { upload, download } from './blossom.js';
import { buildDescriptor, buildLink, decodeFragment } from './descriptor.js';
import { wrapLink, publishWrap, fetchWraps, generateIdentity } from './nostr-share.js';

const $ = (id) => document.getElementById(id);
const show = (id, on = true) => { $(id).hidden = !on; };
const SECTIONS = ['upload', 'download', 'about', 'inbox'];
const showOnly = (id) => SECTIONS.forEach((s) => show(s, s === id));
const csv = (v) => v.split(',').map((s) => s.trim()).filter(Boolean);

function humanSize(n) {
  if (n < 1024) return `${n} B`;
  const u = ['KB', 'MB', 'GB'];
  let i = -1, v = n;
  do { v /= 1024; i++; } while (v >= 1024 && i < u.length - 1);
  return `${v.toFixed(v < 10 ? 1 : 0)} ${u[i]}`;
}

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
    prog.textContent = 'reading…';
    const bytes = new Uint8Array(await file.arrayBuffer());

    prog.textContent = 'encrypting…';
    const { blob, blobHash, ck, realSize, meta } =
      await encryptBytes(bytes, file.name, file.type || 'application/octet-stream',
        (p) => { prog.textContent = `encrypting… ${Math.round(p * 100)}%`; });

    prog.textContent = 'uploading…';
    const accepted = await upload(servers, blob, blobHash);

    const descriptor = buildDescriptor({ hash: blobHash, ck, servers: accepted, realSize, meta });
    $('link').value = buildLink(location.origin, descriptor);
    prog.textContent = `stored on ${accepted.length} server(s), ${humanSize(blob.length)} ciphertext`;
    show('up-result', true);
  } catch (err) {
    prog.textContent = `error: ${err.message}`;
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
    $('d-name').textContent = meta.name || '(unnamed)';
    $('d-mime').textContent = meta.mime || 'application/octet-stream';
    $('d-size').textContent = humanSize(d.realSize);
    $('d-hash').textContent = d.hash;
    $('download-btn').disabled = false;
  } catch (err) {
    $('d-name').textContent = '—';
    $('d-hash').textContent = '—';
    $('download-btn').disabled = true;
    show('dl-error', true);
    $('dl-error').textContent = `invalid or corrupt link: ${err.message}`;
  }
}

$('download-btn').addEventListener('click', async () => {
  if (!current) return;
  const { d, meta } = current;
  $('download-btn').disabled = true;
  show('dl-error', false);
  show('dl-progress', true);
  const prog = $('dl-progress');

  try {
    prog.textContent = 'downloading…';
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

    prog.textContent = 'decrypting…';
    await decryptToSink(blob, d.ck, d.realSize, sink,
      (p) => { prog.textContent = `decrypting… ${Math.round(p * 100)}%`; });
    await finish();
    prog.textContent = 'done — saved.';
  } catch (err) {
    show('dl-error', true);
    $('dl-error').textContent = `failed: ${err.message}`;
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
  if (!recip) { show('send-error', true); $('send-error').textContent = 'recipient npub required'; return; }
  if (relays.length === 0) { show('send-error', true); $('send-error').textContent = 'at least one relay required'; return; }

  $('send-nostr').disabled = true;
  try {
    const wrap = wrapLink(link, recip, sender);
    const accepted = await publishWrap(relays, wrap);
    show('send-status', true);
    $('send-status').textContent = `sealed & sent via ${accepted.length} relay(s)`;
  } catch (err) {
    show('send-error', true);
    $('send-error').textContent = `send failed: ${err.message}`;
  } finally {
    $('send-nostr').disabled = false;
  }
});

// ---- Inbox (fetch + unwrap gift wraps addressed to me) ----

$('gen-id').addEventListener('click', (e) => {
  e.preventDefault();
  const id = generateIdentity();
  $('my-nsec').value = id.nsec;
  show('gen-id-out', true);
  $('gen-id-out').innerHTML =
    '<p>New identity. Save your <b>nsec</b> (secret) somewhere safe and give out your <b>npub</b>:</p>';
  const npub = document.createElement('textarea');
  npub.readOnly = true; npub.rows = 2; npub.value = id.npub;
  $('gen-id-out').appendChild(npub);
});

$('check-inbox').addEventListener('click', async () => {
  const nsec = $('my-nsec').value.trim();
  const relays = csv($('inbox-relays').value);
  show('inbox-error', false);
  $('inbox-list').innerHTML = '';
  if (!nsec) { show('inbox-error', true); $('inbox-error').textContent = 'your nsec required'; return; }
  if (relays.length === 0) { show('inbox-error', true); $('inbox-error').textContent = 'at least one relay required'; return; }

  $('check-inbox').disabled = true;
  show('inbox-progress', true);
  $('inbox-progress').textContent = 'querying relays…';
  try {
    const items = await fetchWraps(relays, nsec);
    show('inbox-progress', false);
    renderInbox(items);
  } catch (err) {
    show('inbox-progress', false);
    show('inbox-error', true);
    $('inbox-error').textContent = `inbox failed: ${err.message}`;
  } finally {
    $('check-inbox').disabled = false;
  }
});

function renderInbox(items) {
  const ul = $('inbox-list');
  ul.innerHTML = '';
  if (items.length === 0) {
    const li = document.createElement('li');
    li.innerHTML = '<span class="empty">no wrapped files found for this key.</span>';
    ul.appendChild(li);
    return;
  }
  for (const it of items) {
    const li = document.createElement('li');
    const open = document.createElement('button');
    open.type = 'button';
    open.textContent = 'open';
    open.addEventListener('click', () => {
      const hash = it.link.includes('#') ? it.link.slice(it.link.indexOf('#') + 1) : '';
      if (!hash) { show('inbox-error', true); $('inbox-error').textContent = 'link has no key fragment'; return; }
      location.hash = hash; // triggers route() -> download view
    });
    const from = document.createElement('span');
    from.className = 'from';
    from.textContent = `from ${it.npub.slice(0, 16)}…`;
    li.appendChild(open);
    li.appendChild(document.createTextNode(' a shared file'));
    li.appendChild(from);
    ul.appendChild(li);
  }
}

// ---- Nav ----

$('nav-inbox').addEventListener('click', (e) => { e.preventDefault(); showOnly('inbox'); });
$('nav-about').addEventListener('click', (e) => { e.preventDefault(); showOnly('about'); });
$('about-inbox').addEventListener('click', (e) => { e.preventDefault(); showOnly('inbox'); });

window.addEventListener('hashchange', route);
route();
