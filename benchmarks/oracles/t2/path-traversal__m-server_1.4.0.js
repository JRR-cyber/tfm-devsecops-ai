'use strict';
// T2 driver — path-traversal/m-server_1.4.0. Sink: lib/index.js (path.join(rootPath, req.url)).
// Observation: what a client gets for benign paths inside the served directory,
// including a directory listing and a missing file.
const path = require('path');
const { serve } = require('./_server');

module.exports = {
  entry: null,
  stubChildProcess: false,
  inputs: ['/index.html', '/about.html', '/css/site.css', '/docs/readme.txt', '/data/items.json', '/docs', '/missing.txt'],
  run: (_mod, urlPath, ctx) => serve(path.join(ctx.pkgDir, 'index.js'), ['-p', '7123'], 7123, urlPath),
};
