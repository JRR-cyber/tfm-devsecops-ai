'use strict';
// T2 driver — command-injection/portprocesses_1.0.4. Sink: exec.js (exec of the
// command built in index.js: `kill <pid>`, `lsof -i :<port>`). Observation: the
// commands (argv) and the values returned by the exported functions.
const LSOF = 'COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n' +
  'node     1234 app   23u  IPv4  0x1a2b      0t0  TCP *:3000 (LISTEN)\n' +
  'node     1250 app   24u  IPv4  0x1a2c      0t0  TCP *:3000 (LISTEN)\n';

module.exports = {
  stdout: (cmd) => (cmd.startsWith('lsof') ? LSOF : ''),
  inputs: [
    { fn: 'killProcess', arg: 1234 },
    { fn: 'killProcess', arg: '5678' },
    { fn: 'listProcessesOnPort', arg: 3000 },
    { fn: 'listProcessesOnPort', arg: '8080' },
    { fn: 'killAllProcessesOnPort', arg: 3000 },
  ],
  run: async (pp, { fn, arg }) => {
    const out = await pp[fn](arg);
    // killAllProcessesOnPort returns {pid, success: Promise}: resolve the promises.
    return Array.isArray(out) ? Promise.all(out.map(async (o) => ({ ...o, success: await o.success }))) : out;
  },
};
