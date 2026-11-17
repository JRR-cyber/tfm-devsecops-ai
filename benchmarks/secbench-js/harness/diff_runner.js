'use strict';
// Differential functional oracle T2 (decision D9, Phase 4.8b).
//
//   node diff_runner.js compare <driver.js> <orig pkg dir> <patched pkg dir>
//   node diff_runner.js run     <driver.js> <pkg dir> <input index>
//
// A case driver (benchmarks/oracles/t2/<case>.js, pre-registered) exports:
//   inputs            benign inputs, fixed before any Phase 5 patch exists
//   run(mod, input, ctx)   calls the package's vulnerable entry point with one
//                     input and returns a JSON-serialisable observation
//   entry             module path inside the package (default: package main);
//                     null = do not require (e.g. a server started as a process)
//   stdout(cmd, argv) fake output of an intercepted command (default "")
//   compareCalls      false = compare only run()'s observation, not the commands
//   platform          value os.platform() reports (reach a platform-specific sink)
//   stubChildProcess  false = real child_process (servers)
//
// `run` executes ONE input against ONE installation in a fresh process (no state
// leaks between inputs or versions) and prints {calls, result, error} as JSON.
// `compare` runs every input against both installations and exits 0 if all the
// observations are identical, 1 if any differs (printing the differences),
// 2 if the driver fails on the original package (an oracle bug, not a patch
// outcome). Strings are normalised: each installation directory becomes <PKG>.
//
// Intercepted commands are recorded as argv, not raw strings, so equivalent
// forms compare equal: exec("git reset 'x'") == execFile("git", ["reset", "x"]).
// Shell strings are split into pipeline segments; `echo X | cmd` is recorded as
// cmd with stdin X (== execFileSync(cmd, args, {input: X})).

const path = require('path');
const util = require('util');
const { spawnSync } = require('child_process');
const { EventEmitter } = require('events');
const { PassThrough } = require('stream');

const TIMEOUT_MS = 20000;
const OPERATORS = new Set(['|', '||', '&&', ';', '&']);

function shellSplit(cmd) {
  // POSIX-ish tokenizer: quotes, backslash escapes and control operators.
  const tokens = [];
  let cur = null;
  let i = 0;
  const push = () => { if (cur !== null) { tokens.push(cur); cur = null; } };
  while (i < cmd.length) {
    const c = cmd[i];
    if (c === "'") {
      const end = cmd.indexOf("'", i + 1);
      cur = (cur || '') + cmd.slice(i + 1, end === -1 ? cmd.length : end);
      i = end === -1 ? cmd.length : end + 1;
    } else if (c === '"') {
      let j = i + 1;
      let s = '';
      while (j < cmd.length && cmd[j] !== '"') {
        if (cmd[j] === '\\' && j + 1 < cmd.length && '"\\$`'.includes(cmd[j + 1])) { s += cmd[j + 1]; j += 2; } else { s += cmd[j]; j += 1; }
      }
      cur = (cur || '') + s;
      i = j + 1;
    } else if (c === '\\' && i + 1 < cmd.length) {
      cur = (cur || '') + cmd[i + 1];
      i += 2;
    } else if (/\s/.test(c)) {
      push();
      i += 1;
    } else if ('|;&'.includes(c)) {
      push();
      const two = cmd.slice(i, i + 2);
      if (OPERATORS.has(two)) { tokens.push({ op: two }); i += 2; } else { tokens.push({ op: c }); i += 1; }
    } else {
      cur = (cur || '') + c;
      i += 1;
    }
  }
  push();
  return tokens;
}

function segments(cmd) {
  // [{argv, stdin?}] for one shell command string.
  const out = [];
  let argv = [];
  let pendingStdin;
  for (const t of shellSplit(cmd)) {
    if (typeof t === 'object') {
      if (t.op === '|' && argv[0] === 'echo') {
        pendingStdin = argv.slice(1).join(' ');
      } else if (argv.length) {
        out.push(pendingStdin !== undefined ? { argv, stdin: pendingStdin } : { argv });
        pendingStdin = undefined;
      }
      argv = [];
    } else {
      argv.push(t);
    }
  }
  if (argv.length) out.push(pendingStdin !== undefined ? { argv, stdin: pendingStdin } : { argv });
  return out;
}

function installStubs(driver, calls) {
  const cp = require('child_process');
  const record = (raw, segs, opts) => {
    for (const s of segs) {
      const call = { argv: s.argv };
      const stdin = s.stdin !== undefined ? s.stdin : opts && opts.input !== undefined ? String(opts.input).replace(/\n$/, '') : undefined;
      if (stdin !== undefined) call.stdin = stdin;
      if (opts && opts.cwd) call.cwd = String(opts.cwd);
      calls.push(call);
    }
    return driver.stdout ? String(driver.stdout(raw, segs.map((s) => s.argv)) || '') : '';
  };
  const asOutput = (s, opts) => (opts && opts.encoding && opts.encoding !== 'buffer' ? s : Buffer.from(s));
  const split = (args) => {
    // (cmd|file, [args], [opts], [cb]) -> {args, opts, cb}
    let a = [];
    let o = {};
    let cb;
    for (const x of args) {
      if (typeof x === 'function') cb = x;
      else if (Array.isArray(x)) a = x;
      else if (x && typeof x === 'object') o = x;
    }
    return { a, o, cb };
  };
  const fakeChild = (out) => {
    const child = new EventEmitter();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.stdin = new PassThrough();
    child.pid = 4242;
    child.kill = () => true;
    setImmediate(() => {
      child.stdout.end(out);
      child.stderr.end();
      setImmediate(() => { child.emit('exit', 0, null); child.emit('close', 0, null); });
    });
    return child;
  };

  cp.exec = function exec(cmd, ...rest) {
    const { o, cb } = split(rest);
    const out = record(cmd, segments(cmd), o);
    if (cb) setImmediate(() => cb(null, asOutput(out, { encoding: o.encoding || 'utf8' }), ''));
    return fakeChild(out);
  };
  cp.exec[util.promisify.custom] = (cmd, opts) => {
    const out = record(cmd, segments(cmd), opts);
    return Promise.resolve({ stdout: out, stderr: '' });
  };
  cp.execSync = (cmd, opts) => asOutput(record(cmd, segments(cmd), opts), opts);
  cp.execFile = function execFile(file, ...rest) {
    const { a, o, cb } = split(rest);
    const argv = [file, ...a.map(String)];
    const out = record(argv.join(' '), [{ argv }], o);
    if (cb) setImmediate(() => cb(null, asOutput(out, { encoding: o.encoding || 'utf8' }), ''));
    return fakeChild(out);
  };
  cp.execFile[util.promisify.custom] = (file, args, opts) => {
    const argv = [file, ...(args || []).map(String)];
    return Promise.resolve({ stdout: record(argv.join(' '), [{ argv }], opts), stderr: '' });
  };
  cp.execFileSync = (file, args, opts) => {
    if (args && !Array.isArray(args)) { opts = args; args = []; }
    const argv = [file, ...(args || []).map(String)];
    return asOutput(record(argv.join(' '), [{ argv }], opts), opts);
  };
  cp.spawn = (cmd, args, opts) => {
    if (args && !Array.isArray(args)) { opts = args; args = []; }
    const segs = opts && opts.shell ? segments([cmd, ...(args || [])].join(' ')) : [{ argv: [cmd, ...(args || []).map(String)] }];
    return fakeChild(record([cmd, ...(args || [])].join(' '), segs, opts));
  };
  cp.spawnSync = (cmd, args, opts) => {
    if (args && !Array.isArray(args)) { opts = args; args = []; }
    const segs = opts && opts.shell ? segments([cmd, ...(args || [])].join(' ')) : [{ argv: [cmd, ...(args || []).map(String)] }];
    const out = record([cmd, ...(args || [])].join(' '), segs, opts);
    return { pid: 4242, status: 0, signal: null, stdout: asOutput(out, opts), stderr: asOutput('', opts), output: [null, out, ''] };
  };
}

function settle(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function runOne(driverPath, pkgDir, index) {
  // The package may print to stdout; only the observation JSON may go there.
  const emit = process.stdout.write.bind(process.stdout);
  process.stdout.write = (...args) => process.stderr.write(...args);
  const driver = require(driverPath);
  const calls = [];
  if (driver.platform) require('os').platform = () => driver.platform;
  if (driver.stubChildProcess !== false) installStubs(driver, calls);
  let result;
  let error;
  try {
    const mod = driver.entry === null ? null : require(path.join(pkgDir, driver.entry || ''));
    result = await Promise.race([
      Promise.resolve(driver.run(mod, driver.inputs[index], { pkgDir })),
      settle(TIMEOUT_MS).then(() => { throw new Error('driver timeout'); }),
    ]);
  } catch (e) {
    error = String((e && e.message) || e);
  }
  await settle(50); // let pending callbacks record their calls
  const obs = { result: result === undefined ? null : result, error: error || null };
  if (driver.compareCalls !== false) obs.calls = calls;
  emit(JSON.stringify(obs), () => process.exit(0));
}

function observe(driverPath, pkgDir, index) {
  const res = spawnSync(process.execPath, [__filename, 'run', driverPath, pkgDir, String(index)],
    { encoding: 'utf8', timeout: TIMEOUT_MS + 10000, cwd: process.cwd() });
  if (res.status !== 0 || !res.stdout) {
    return { crash: `exit ${res.status}: ${(res.stderr || '').trim().split('\n').slice(-3).join(' | ')}` };
  }
  return JSON.parse(res.stdout);
}

function normalise(obs, pkgDir) {
  const root = path.resolve(pkgDir);
  const install = path.resolve(pkgDir, '..', '..'); // <prefix>/node_modules/<pkg>
  return JSON.stringify(obs).split(root).join('<PKG>').split(install).join('<INSTALL>');
}

function compare(driverPath, origDir, patchedDir) {
  const driver = require(driverPath);
  let differ = 0;
  let broken = 0;
  driver.inputs.forEach((input, i) => {
    const a = normalise(observe(driverPath, origDir, i), origDir);
    const b = normalise(observe(driverPath, patchedDir, i), patchedDir);
    if (a.includes('"crash"')) {
      broken += 1;
      console.log(`DRIVER_ERROR input #${i} ${JSON.stringify(input)}: ${a}`);
    } else if (a !== b) {
      differ += 1;
      console.log(`DIFF input #${i} ${JSON.stringify(input)}\n  original: ${a.slice(0, 600)}\n  patched:  ${b.slice(0, 600)}`);
    } else {
      console.log(`SAME input #${i}: ${a.slice(0, 300)}`);
    }
  });
  console.log(`${driver.inputs.length} inputs: ${driver.inputs.length - differ - broken} same, ${differ} different, ${broken} driver errors`);
  process.exit(broken ? 2 : differ ? 1 : 0);
}

const [mode, driverPath, a, b] = process.argv.slice(2);
if (mode === 'run') runOne(path.resolve(driverPath), path.resolve(a), Number(b));
else if (mode === 'compare') compare(path.resolve(driverPath), path.resolve(a), path.resolve(b));
else { console.error('usage: diff_runner.js compare|run ...'); process.exit(64); }
