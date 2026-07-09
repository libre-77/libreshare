// Minimal Blossom (BUD-01/02) server for local dev. Zero dependencies.
// Content-addressed: a blob's URL is the sha256 of its bytes. Stores ciphertext
// only — it has no keys and cannot read anything. Auth is intentionally skipped
// here; a real deployment requires signed kind:24242 upload auth.

import http from 'node:http';
import { createHash } from 'node:crypto';
import { mkdirSync, existsSync, readFileSync, writeFileSync, statSync, unlinkSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const STORE = join(HERE, 'blobs');
const PORT = process.env.PORT || 3000;
mkdirSync(STORE, { recursive: true });

const HEX64 = /^[0-9a-f]{64}$/;

function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, PUT, HEAD, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers',
    'Authorization, Content-Type, X-SHA-256, X-Content-Length, X-Content-Type');
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  cors(res);
  const url = new URL(req.url, `http://${req.headers.host}`);
  const path = url.pathname.slice(1);

  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }

  // BUD-06 upload requirements: answer whether a blob of X-Content-Length bytes
  // would be accepted, without a body. This mock caps at MAX_BLOB to let the app
  // exercise its size-limit detection locally.
  if (req.method === 'HEAD' && path === 'upload') {
    const MAX_BLOB = Number(process.env.MAX_BLOB || 25 * 1024 * 1024);
    const want = Number(req.headers['x-content-length'] || 0);
    res.writeHead(want > MAX_BLOB ? 413 : 200);
    return res.end();
  }

  if (req.method === 'PUT' && path === 'upload') {
    const body = await readBody(req);
    const sha256 = createHash('sha256').update(body).digest('hex');
    writeFileSync(join(STORE, sha256), body);
    res.writeHead(201, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({
      url: `http://localhost:${PORT}/${sha256}`,
      sha256, size: body.length, uploaded: Math.floor(Date.now() / 1000),
    }));
  }

  if (HEX64.test(path)) {
    const file = join(STORE, path);
    if (!existsSync(file)) { res.writeHead(404); return res.end('not found'); }
    if (req.method === 'HEAD') {
      res.writeHead(200, { 'Content-Length': statSync(file).size });
      return res.end();
    }
    if (req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/octet-stream' });
      return res.end(readFileSync(file));
    }
    if (req.method === 'DELETE') {
      unlinkSync(file);
      res.writeHead(200); return res.end('deleted');
    }
  }

  res.writeHead(404); res.end('not found');
});

server.listen(PORT, () => console.log(`blossom-mock on http://localhost:${PORT}`));
