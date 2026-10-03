# PortProcesses

## Install

    npm install -g portprocesses

## Usage

### CLI

The following command will list all processes running on port `8000`. You can replace `8000` with any port to get the processes running on that port. The output will be in JSON format.

    portprocesses list 8000

The following command will kill all processes running on port `8000`. You can replace `8000` with any port to kill the processes running on that port.

    portprocesses kill 8000

### Node.js

The following code will list all processes running on port `8000`. You can replace `8000` with any port to get the processes running on that port.

```js
const portprocesses = require('portprocesses');
const promise = portprocesses.listProcessesOnPort(8000); // this returns a promise
promise.then((result) => {
	console.log(result); // JSON array
	// [ { command: 'node',
	// pid: '123',
	// user: 'user',
	// fd: '22u',
	// type: 'IPv4',
	// device: '0x01abc3456d789012',
	// 'size/off': '0t0',
	// node: 'TCP',
	// name: '10.0.0.1:12345->123.456.7.89:http (CLOSE_WAIT)' } ]
});
promise.catch((err) => {
	console.error(err);
});
```

The following code will kill all processes running on port `8000`. You can replace `8000` with any port to kill the processes running on that port.

```js
const portprocesses = require('portprocesses');
const promise = portprocesses.killAllProcessesOnPort(8000); // this returns a promise
promise.then((result) => {
	console.log(result); // JSON array
	// [ { pid: '123'
	// success: true } ]
});
promise.catch((err) => {
	console.error(err);
});
```

In this case success for a given process can be false without the process throwing an error. Therefor upon success of the promise it's recommended to check the array for any items that have `success` set to `false`.
