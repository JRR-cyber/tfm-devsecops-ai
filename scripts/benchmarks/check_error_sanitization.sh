#!/usr/bin/env bash
# GATE evidence for the stack-trace-exposure family (docs/benchmark/triage-labels.md, D7).
# The flagged sinks return either utils.getErrorMessage(error) -- only the message --
# or res.json(err) where err is an Error, which serializes to {}. Either way no stack
# trace reaches the client, so the findings are false positives.
#
# Usage: scripts/benchmarks/check_error_sanitization.sh   (needs the tfm/juice-shop:ci image)
set -euo pipefail
docker run --rm tfm/juice-shop:ci -e '
const u = require("/juice-shop/build/lib/utils.js");
const e = new Error("boom"); e.stack = "SECRET-STACK at /app/x.js:1";
const msg = u.getErrorMessage(e);
const ok = msg === "boom" && !String(msg).includes("SECRET-STACK") && JSON.stringify(e) === "{}";
process.exit(ok ? 0 : 1);
'
echo "GATE ok: getErrorMessage returns only the message; an Error serializes to {}"
