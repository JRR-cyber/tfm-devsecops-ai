#!/usr/bin/env bash
# Run one triage-evidence exploit (docs/benchmark/triage-labels.md) against one
# version of an npm package, optionally with a guard removed (ablation).
#
#   run_evidence <package> <version> <test.js> [<ablation.json>]
#
# <test.js> is a Jest test that passes when the exploit succeeds.
# <ablation.json> is a list of {"file": "<path inside the package>", "old": "...", "new": "..."};
# each "old" must occur exactly once in its file.
#
# Exit codes: 0 = exploit succeeded
#             1 = exploit failed
#             3 = the package version could not be installed
#             4 = the ablation does not apply (code changed)
set -u

pkg="$1" ver="$2" test="$3" ablation="${4:-}"
dir="/exploit/evidence"

rm -rf "$dir" && mkdir -p "$dir"
cp "$test" "$dir/"
cd "$dir"
printf '{"name":"triage-evidence","version":"1.0.0","private":true}\n' > package.json

# --ignore-scripts: never run install hooks of old, known-vulnerable packages.
if ! npm install --no-audit --no-fund --ignore-scripts "$pkg@$ver" > install.log 2>&1; then
  echo "INSTALL_FAILED $pkg@$ver"
  tail -n 20 install.log
  exit 3
fi

if [ -n "$ablation" ]; then
  node -e '
    const fs = require("fs");
    const [abl, pkgDir] = process.argv.slice(1);
    for (const { file, old, new: repl } of JSON.parse(fs.readFileSync(abl, "utf8"))) {
      const target = `${pkgDir}/${file}`;
      const src = fs.readFileSync(target, "utf8");
      if (src.split(old).length !== 2) { console.error(`ABLATION_MISMATCH ${target}`); process.exit(4); }
      fs.writeFileSync(target, src.replace(old, () => repl));
      console.log(`ablation applied to ${file}`);
    }
  ' "$ablation" "node_modules/$pkg" || exit 4
fi

jest --ci --runInBand --rootDir "$dir" --testTimeout 60000
