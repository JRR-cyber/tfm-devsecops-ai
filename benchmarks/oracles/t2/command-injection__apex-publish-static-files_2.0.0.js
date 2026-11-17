'use strict';
// T2 driver — command-injection/apex-publish-static-files_2.0.0. Sink: index.js
// (execSync of the SQLcl command line). Observation: publish()'s return value or
// validation error, and the SQLcl command it would run (intercepted, as argv).
module.exports = {
  inputs: [
    { connectString: 'scott/tiger@localhost:1521/ORCLPDB1', directory: './', appID: 111 },
    { connectString: 'admin/s3cret@db.example.com:1521/pdb1', directory: './', appID: 200, destination: 'theme' },
    { connectString: 'dev/dev@127.0.0.1:1521/XE', directory: './', appID: 300, destination: 'workspace', sqlclPath: '/opt/sqlcl/bin/sql' },
    { connectString: 'dev/dev@127.0.0.1:1521/XE', directory: './', appID: 400, destination: 'plugin', pluginName: 'COM.EXAMPLE.PLUGIN' },
    { connectString: 'dev/dev@127.0.0.1:1521/XE', directory: './', appID: 500, destination: 'plugin' },
    { directory: './', appID: 600 },
    { connectString: 'dev/dev@127.0.0.1:1521/XE', directory: './no-such-dir', appID: 700 },
  ],
  run: (mod, opts) => mod.publish(JSON.parse(JSON.stringify(opts))),
};
