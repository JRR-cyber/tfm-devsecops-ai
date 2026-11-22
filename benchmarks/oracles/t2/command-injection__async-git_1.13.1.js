'use strict';
// T2 driver — command-injection/async-git_1.13.1. Sink: lib/reset/index.js
// (exec of `git reset <destination>`). Observation: the git command run (argv) and
// the resolved value or error, for string and numeric destinations.
module.exports = {
  stdout: () => 'HEAD is now at 1a2b3c4 previous commit\n',
  inputs: [
    ['HEAD~1'],
    ['main'],
    ['origin/main', { hard: false }],
    ['1a2b3c4d5e6f'],
    ['v1.2.0', { hard: true }],
    [2],
    [3, { hard: false }],
    [''],
  ],
  run: (git, [destination, options]) => git.reset(destination, options),
};
