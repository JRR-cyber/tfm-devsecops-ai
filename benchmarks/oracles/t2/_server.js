'use strict';
// Shared helper of the path-traversal T2 drivers (decision D9): start the package's
// server in a fixture site, request ONE benign path, stop the server, and return
// what a client sees (status, content type, body). The fixture is recreated
// identically for every run, so original and patched servers serve the same files.

const fs = require('fs');
const http = require('http');
const path = require('path');
const { spawn } = require('child_process');

const SITE = '/tmp/tfm-t2-site';
const FILES = {
  'index.html': '<!doctype html><title>home</title><p>Welcome</p>\n',
  'about.html': '<!doctype html><title>about</title><p>About us</p>\n',
  'css/site.css': 'body { margin: 0; color: #333; }\n',
  'docs/readme.txt': 'Plain text document.\nSecond line.\n',
  'data/items.json': '{"items": [1, 2, 3]}\n',
};

// The path stays fixed (not mkdtemp) so both runs see the same paths in any
// response. It is created private: the top directory non-recursively with 0700,
// so it fails with EEXIST if someone recreated it after the rm (no symlink or
// pre-planted directory is followed), and the files 0600 (CodeQL
// js/insecure-temporary-file).
function makeSite() {
  fs.rmSync(SITE, { recursive: true, force: true });
  fs.mkdirSync(SITE, { mode: 0o700 });
  for (const [rel, content] of Object.entries(FILES)) {
    fs.mkdirSync(path.dirname(path.join(SITE, rel)), { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(SITE, rel), content, { mode: 0o600 });
  }
}

function get(port, urlPath) {
  return new Promise((resolve) => {
    const req = http.get({ host: '127.0.0.1', port, path: urlPath, timeout: 3000 }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({
        status: res.statusCode,
        contentType: res.headers['content-type'] || null,
        body: Buffer.concat(chunks).toString('utf8'),
      }));
    });
    req.on('error', (e) => resolve({ error: e.code || e.message }));
    req.on('timeout', () => req.destroy(new Error('timeout')));
  });
}

async function waitForPort(port, ms) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const ok = await new Promise((resolve) => {
      const s = require('net').connect(port, '127.0.0.1', () => { s.end(); resolve(true); });
      s.on('error', () => resolve(false));
    });
    if (ok) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`server did not listen on ${port}`);
}

async function serve(script, args, port, urlPath) {
  makeSite();
  const child = spawn(process.execPath, [script, ...args], { cwd: SITE, stdio: 'ignore' });
  try {
    await waitForPort(port, 8000);
    return await get(port, urlPath);
  } finally {
    child.kill('SIGKILL');
    await new Promise((r) => child.once('exit', r));
  }
}

module.exports = { serve, SITE };
