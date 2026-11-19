'use strict';
// T2 driver — command-injection/giting_0.0.7. Sink: lib/git.js (exec of
// `git pull ... <branch>` and `git fetch/checkout` built by joining strings).
// Observation: the git commands (argv, working directory) and the callback error
// for pull (existing checkout) and update (new checkout: init + fetch + checkout).
// The working directory is fixed and recreated each run, so both versions see the
// same file system.
const fs = require('fs');

const ROOT = '/tmp/tfm-t2-giting';

module.exports = {
  inputs: [
    { action: 'pull', repo: { organization: 'acme', name: 'web', branch: 'main', commit: 'a1b2c3d' } },
    { action: 'pull', repo: { organization: 'acme', name: 'api', branch: 'develop', commit: 'e4f5a6b' } },
    { action: 'pull', repo: { organization: 'team', name: 'docs', branch: 'feature/login', commit: '0011223' } },
    { action: 'update', repo: { organization: 'acme', name: 'web', branch: 'release-1.2', commit: '9f8e7d6' } },
    { action: 'update', repo: { organization: 'team', name: 'tools', branch: 'main', commit: 'abcdef0' } },
  ],
  run: (Git, { action, repo }) => {
    fs.rmSync(ROOT, { recursive: true, force: true });
    fs.mkdirSync(ROOT, { recursive: true });
    const git = new Git({ dir: ROOT, workDir: `${ROOT}/checkouts`, repoDir: `${ROOT}/repos` });
    return new Promise((resolve) => {
      git[action]({ ...repo }, (err) => resolve({ err: err ? String(err.message || err) : null }));
    });
  },
};
