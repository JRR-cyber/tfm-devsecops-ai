#!/usr/bin/env bash
# Differential functional oracle T2 (decision D9, Phase 4.8b).
#
#   run_diff <package> <version> <driver file name>
#
# Mounts:
#   /pkg   (ro) the patched package: the case's src/ from the worktree
#   /t2    (ro) benchmarks/oracles/t2 (pre-registered drivers)
#
# Installs the published vulnerable version twice: /diff/orig as published, and
# /diff/patched with /pkg overlaid on node_modules/<package> (src/ is the npm
# tarball of that version, so only the patch differs). diff_runner.js then runs
# every pre-registered benign input of the driver against both and compares.
#
# Exit codes: 0 = same observations for every input
#             1 = at least one input behaves differently (functional regression)
#             2 = the driver fails on the original package (oracle bug)
#             3 = the package version could not be installed
set -u
export npm_config_ignore_scripts=true

pkg="$1" ver="$2" driver="/t2/$3"
for side in orig patched; do
  mkdir -p "/diff/$side" && cd "/diff/$side"
  printf '{"name":"t2-%s","version":"1.0.0","private":true}\n' "$side" > package.json
  if ! npm install --no-audit --no-fund "$pkg@$ver" > install.log 2>&1; then
    echo "INSTALL_FAILED $pkg@$ver"
    tail -n 20 install.log
    exit 3
  fi
done
cp -a /pkg/. "/diff/patched/node_modules/$pkg/"

mkdir -p /diff/cwd && cd /diff/cwd   # neutral working directory for the drivers
node /usr/local/lib/diff_runner.js compare "$driver" \
  "/diff/orig/node_modules/$pkg" "/diff/patched/node_modules/$pkg"
