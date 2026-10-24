# Exploit-reproduction harness for the SecBench.js subset of the benchmark.
#
# SecBench.js has no license file, so its exploits are not vendored into this
# repository: they are fetched here from a pinned upstream commit.
#
#   docker build -t tfm/secbench-harness benchmarks/secbench-js/harness
#   docker run --rm tfm/secbench-harness run_case <class> <case> <package> <version>
#
# Node 16 is the runtime SecBench.js was validated on (README: Node >= 16.3).
# bookworm rather than upstream's bullseye: bullseye is EOL and its security
# mirror no longer serves the packages below.
FROM node:16-bookworm

# Tools the exploits shell out to (curl, fuser from psmisc, zip) and the
# toolchain for native modules such as `sleep`.
RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl zip psmisc g++ make python3 \
    && rm -rf /var/lib/apt/lists/*

ARG SECBENCH_REPO=https://github.com/cristianstaicu/SecBench.js.git
ARG SECBENCH_COMMIT=5d362353550a8baa42bba34edd26e5fb86d41b60
RUN git init -q /secbench \
    && git -C /secbench fetch -q --depth 1 "$SECBENCH_REPO" "$SECBENCH_COMMIT" \
    && git -C /secbench checkout -q FETCH_HEAD

RUN npm install -g --no-audit --no-fund jest@29.7.0

# Shared helpers resolved by the exploit tests from /exploit/node_modules:
# path-traversal exploits `require("sleep")` to wait for the target server.
WORKDIR /exploit
RUN npm init -y >/dev/null && npm install --no-audit --no-fund sleep@6.3.0

COPY run_case.sh /usr/local/bin/run_case
RUN chmod +x /usr/local/bin/run_case
