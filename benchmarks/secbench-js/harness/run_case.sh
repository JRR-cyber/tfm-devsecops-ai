#!/usr/bin/env bash
# Run one SecBench.js exploit against one version of the vulnerable package.
#
#   run_case <class> <case> <package> <version>
#
# Patched code (Phase 4.8, decision D9): if PATCHED_SRC points to a directory
# (the case's src/ from the patched worktree, mounted read-only), it is copied
# over node_modules/<package> after the install. src/ is the npm tarball of that
# exact version, so the result is the published package with the patch applied
# and the published dependencies.
#
# Exit codes: 0 = exploit succeeded (the version is vulnerable)
#             1 = exploit failed    (the version is not exploitable)
#             3 = the package version could not be installed
#             4 = PATCHED_SRC was given but could not be overlaid
set -u

cls="$1" case="$2" pkg="$3" ver="$4"
src="/secbench/$cls/$case"
dir="/exploit/$cls/$case"

# Exploits reach shared files through relative paths: ../utils.js (redos)
# and ../flag.html (path-traversal, the file the traversal tries to read).
mkdir -p "/exploit/$cls"
for shared in utils.js flag.html; do
  [ -f "/secbench/$cls/$shared" ] && cp "/secbench/$cls/$shared" "/exploit/$cls/"
done

rm -rf "$dir" && mkdir -p "$dir"
cp "$src"/*.test.js "$dir/"
cd "$dir"
printf '{"name":"secbench-case","version":"1.0.0","private":true}\n' > package.json

# --ignore-scripts: never run install hooks of old, known-vulnerable packages.
if ! npm install --no-audit --no-fund --ignore-scripts "$pkg@$ver" > install.log 2>&1; then
  echo "INSTALL_FAILED $pkg@$ver"
  tail -n 20 install.log
  exit 3
fi

if [ -n "${PATCHED_SRC:-}" ]; then
  if [ ! -f "$PATCHED_SRC/package.json" ] || [ ! -d "node_modules/$pkg" ]; then
    echo "PATCH_OVERLAY_FAILED $PATCHED_SRC -> node_modules/$pkg"
    exit 4
  fi
  cp -a "$PATCHED_SRC/." "node_modules/$pkg/"
  echo "patched source overlaid on node_modules/$pkg"
fi

jest --ci --runInBand --rootDir "$dir" --testTimeout 60000
