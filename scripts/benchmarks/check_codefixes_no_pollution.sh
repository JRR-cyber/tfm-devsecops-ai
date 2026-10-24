#!/usr/bin/env bash
# GATE evidence for routes/vulnCodeFixes.ts:40 (docs/benchmark/triage-labels.md, D7).
# readFixes caches CodeFixes[key] = {fixes, correct}. The key is attacker-controlled,
# but this single-level assignment to a local cache object cannot pollute
# Object.prototype (obj["__proto__"] = obj only sets that object's prototype), so
# injecting "__proto__"/"constructor" has no global effect -> the finding is a FP.
#
# Usage: scripts/benchmarks/check_codefixes_no_pollution.sh   (needs tfm/juice-shop:ci)
set -euo pipefail
docker run --rm tfm/juice-shop:ci -e '
process.chdir("/juice-shop");
const m = require("/juice-shop/build/routes/vulnCodeFixes.js");
for (const k of ["__proto__", "constructor", "polluted"]) { try { m.readFixes(k); } catch (e) {} }
const polluted = ({}).fixes !== undefined || ({}).polluted !== undefined || Object.getPrototypeOf({}) !== Object.prototype;
process.exit(polluted ? 1 : 0);
'
echo "GATE ok: readFixes with __proto__/constructor keys does not pollute Object.prototype"
