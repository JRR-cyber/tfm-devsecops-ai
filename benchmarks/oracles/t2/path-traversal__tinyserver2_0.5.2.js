'use strict';
// T2 driver — path-traversal/tinyserver2_0.5.2. Sink: tinyserver.js (readFile of
// cwd + pathname). Observation: response to benign paths and "/" (index.html).
// A missing file is left out: the original answers 200 with an empty body, which
// a fix may legitimately turn into a 404.
const path = require('path');
const { serve } = require('./_server');

module.exports = {
  entry: null,
  stubChildProcess: false,
  inputs: ['/', '/index.html', '/about.html', '/css/site.css', '/docs/readme.txt', '/data/items.json'],
  run: (_mod, urlPath, ctx) => serve(path.join(ctx.pkgDir, 'tinyserver.js'), ['-p', '8976'], 8976, urlPath),
};
