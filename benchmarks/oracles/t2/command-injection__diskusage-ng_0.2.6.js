'use strict';
// T2 driver — command-injection/diskusage-ng_0.2.6. Sink: lib/posix.js (exec of
// `df -k "<path>"`). Observation: the df command (argv) and the parsed usage.
module.exports = {
  stdout: () => 'Filesystem     1K-blocks    Used Available Use% Mounted on\n' +
    '/dev/sda1       41152736 9876543  29163489  26% /\n',
  inputs: ['/', '/tmp', '/var/log', '/home/user/My Documents', 'relative/dir', '/mnt/data-01'],
  run: (diskusage, p) => new Promise((resolve) => {
    diskusage(p, (err, usage) => resolve({ err: err ? String(err.message || err) : null, usage: usage || null }));
  }),
};
