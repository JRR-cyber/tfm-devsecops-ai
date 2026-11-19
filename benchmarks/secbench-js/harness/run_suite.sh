#!/usr/bin/env bash
# Run a SecBench.js package's own test suite: functional oracle T1 (decision D9,
# Phase 4.8).
#
#   run_suite <command...>
#
# Mounts:
#   /pkg                (ro) the package: the case's src/ (the npm tarball of the
#                       version), unpatched for the base run or patched from the
#                       worktree.
#   /tests              (ro, optional) test files from the upstream repository at
#                       the version's commit, overlaid on the package when the
#                       tarball ships none.
#   /work/node_modules  (optional named volume) dependency cache: a patch only
#                       changes the package's own code, never its dependencies.
# Env:
#   EXTRA_DEV           extra npm packages the suite needs but does not declare
#                       (e.g. a test runner pinned to a version that runs on Node 16).
#
# Exit codes: the test command's own exit code (0 = suite passed),
#             3 = dependencies could not be installed.
set -u
export npm_config_ignore_scripts=true   # no install hooks of old packages

mkdir -p /work
find /work -mindepth 1 -maxdepth 1 ! -name node_modules -exec rm -rf {} +
cp -a /pkg/. /work/
if [ -d /tests ]; then cp -a /tests/. /work/; fi
cd /work

# shellcheck disable=SC2086
if ! npm install --no-audit --no-fund --no-save ${EXTRA_DEV:-} > /tmp/install.log 2>&1; then
  echo "INSTALL_FAILED"
  tail -n 20 /tmp/install.log
  exit 3
fi

timeout 600 bash -c "$*"
