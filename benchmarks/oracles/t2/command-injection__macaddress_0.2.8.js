'use strict';
// T2 driver — command-injection/macaddress_0.2.8. Sink: lib/unix.js (exec of
// `ifconfig <iface>`), used on non-Linux, non-Windows platforms: os.platform() is
// reported as 'darwin' to reach it (on Linux the package loads lib/linux.js).
// Observation: the ifconfig command (argv) and the MAC address or error returned.
module.exports = {
  platform: 'darwin',
  stdout: (cmd) => (/\ben0\b/.test(cmd)
    ? 'en0: flags=8863<UP,BROADCAST,RUNNING> mtu 1500\n\tether 0a:1b:2c:3d:4e:5f\n\tinet 192.168.1.20 netmask 0xffffff00\n'
    : /\ben1\b/.test(cmd)
      ? 'en1: flags=8863<UP> mtu 1500\n\tether A4:83:E7:12:34:56\n'
      : 'lo0: flags=8049<UP,LOOPBACK,RUNNING> mtu 16384\n\tinet 127.0.0.1 netmask 0xff000000\n'),
  inputs: ['en0', 'en1', 'lo0', 'bridge0', 'utun3'],
  run: (macaddress, iface) => new Promise((resolve) => {
    macaddress.one(iface, (err, mac) => resolve({ err: err ? String(err.message || err) : null, mac: mac || null }));
  }),
};
