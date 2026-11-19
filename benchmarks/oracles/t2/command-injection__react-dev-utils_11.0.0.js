'use strict';
// T2 driver — command-injection/react-dev-utils_11.0.0. Sink: getProcessForPort.js
// (execSync of `lsof -i:<port> ...`). Observation: the commands (argv) and the
// description returned. The fake ps output depends on whether the command pipes
// through `sed -n 2p` (the original) or not (a fix that drops the shell pipe gets
// the raw two-line ps output, as the real ps would print).
const CMD = 'node /home/dev/app/node_modules/react-scripts/scripts/start.js';

module.exports = {
  entry: 'getProcessForPort',
  stdout: (cmd) => {
    if (cmd.startsWith('lsof -i')) return '4321\n';
    if (cmd.includes('awk')) return '/home/dev/app ';
    if (cmd.startsWith('ps')) return cmd.includes('sed') ? `${CMD}\n` : `COMMAND\n${CMD}\n`;
    return '';
  },
  inputs: [3000, 8080, '5000', 443],
  run: (getProcessForPort, port) => getProcessForPort(port),
};
