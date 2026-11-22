'use strict';
// T2 driver — command-injection/thi.ng-egf_0.3.0. Sink: lib/index.js (the `gpg`
// builtin: execSync of `echo "<body>" | gpg --decrypt`). Observation: the gpg
// invocation (argv + data on stdin; `echo X | gpg` and execFileSync('gpg', ...,
// {input: X}) record the same) and the value returned, with decryption on and off.
module.exports = {
  stdout: () => 'decrypted-secret-value\n',
  inputs: [
    { body: 'hQEMA1234567890ABCDEFAQf/abc', decrypt: true },
    { body: 'hQEMAzZyXwVuTsRqPoNmAQgAlong+base64/payload==', decrypt: true },
    { body: 'plain value', decrypt: false },
    { body: '  padded value  ', decrypt: false },
  ],
  run: (egf, { body, decrypt }) => egf.BUILTINS.gpg('secret', body, { opts: { decrypt } }),
};
