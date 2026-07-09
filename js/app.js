import { encryptBytes, decryptToSink, readMeta } from './crypto.js';
import { upload, download } from './blossom.js';
import { buildDescriptor, buildLink, decodeFragment } from './descriptor.js';

const $ = (id) => document.getElementById(id);
const show = (id, on = true) => { $(id).hidden = !on; };

function humanSize(n) {
  if (n < 1024) return `${n} B`;
  const u = ['KB', 'MB', 'GB'];
  let i = -1, v = n;
  do { v /= 1024; i++; } while (v >= 1024 && i < u.length - 1);
  return `${v.toFixed(v < 10 ? 1 : 0)} ${u[i]}`;
}

function route() {
  const frag = location.hash.slice(1);
  const isDownload = frag.length > 0 && $('about').hidden;
  show('about', false);
  if (frag.length > 0) { show('upload', false); show('download', true); renderDownload(frag); }
  else { show('download', false); show('upload', true); }
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

// ---- Nav ----

$('nav-about').addEventListener('click', (e) => {
  e.preventDefault();
  show('upload', false); show('download', false); show('about', true);
});

window.addEventListener('hashchange', route);
route();
