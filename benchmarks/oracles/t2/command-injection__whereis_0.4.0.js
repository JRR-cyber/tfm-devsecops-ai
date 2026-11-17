'use strict';
// T2 driver — command-injection/whereis_0.4.0. Sink: index.js (exec of
// `which <name>`, then `whereis <name>`). Observation: the commands (argv) and the
// path found, for programs found by `which` and one found only by `whereis`.
// Programs found by no command are left out: that path only reaches Windows-only
// fallbacks, which a fix may legitimately drop.
module.exports = {
  stdout: (cmd) => {
    const [tool, name] = cmd.split(' ');
    if (tool === 'which') return name === 'legacy-tool' ? '' : `/usr/bin/${name}\n`;
    if (tool === 'whereis') return `${name}: /opt/legacy/bin/${name} /usr/share/man/man1/${name}.1\n`;
    return '';
  },
  inputs: ['node', 'git', 'python3', 'ls', 'legacy-tool'],
  run: (whereis, name) => new Promise((resolve) => {
    whereis(name, (err, p) => resolve({ err: err ? String(err.message || err) : null, path: p || null }));
  }),
};
