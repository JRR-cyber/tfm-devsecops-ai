'use strict';
// T2 driver — path-traversal/serve-here.js_1.1.0. Sink: source/server.js (readFile of
// RootFolder + req.url). Observation: response to benign paths, the index page for
// "/" and a missing file (404). The CLI always listens on port 8000.
const path = require('path');
const { serve } = require('./_server');

module.exports = {
  entry: null,
  stubChildProcess: false,
  inputs: ['/', '/index.html', '/about.html', '/css/site.css', '/docs/readme.txt', '/data/items.json', '/missing.txt'],
  run: (_mod, urlPath, ctx) => serve(path.join(ctx.pkgDir, 'bin', 'index.js'), [], 8000, urlPath),
};
