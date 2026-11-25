# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project purpose

Master's thesis (TFM, UC3M) project: a Shift-Left DevSecOps pipeline with a **hybrid architecture** — symbolic reachability analysis (dataflow/taint traces) + contextual LLM decisions — for triage and assisted remediation of vulnerabilities. Project docs (README, SECURITY.md) are in Spanish.

Fixed design decisions (roadmap v2 — don't substitute tools without being asked):

- Scanners: Semgrep OSS (SAST), Trivy (SCA + container), TruffleHog (secrets), CodeQL (dataflow/taint `codeFlows`). All output SARIF/JSON, consolidated into one unified artifact that feeds the agent.
- LLM: single fixed model `openai/gpt-oss-120b`. The roadmap's original model, Llama 3.3 70B, was retired by Groq on 2026-08-16; the model switched to Groq's most capable open-weights general model — rationale in `scripts/ai_agent/README.md` "Decisión de modelo". The client defaults to Groq (`GROQ_API_KEY`); **the whole of Phase 5 runs on Together AI** (`LLM_PROVIDER=together`, `TOGETHER_API_KEY`, spend cap `LLM_BUDGET_USD`) per `docs/benchmark/decisions.md` D12, after the provider pilot (`docs/benchmark/piloto-proveedor.md`, C1–C6 passed) — never mix providers within Phase 5. Experiments compare **prompting strategies** (zero-shot / few-shot / CoT), not models.
- Pre/post-patch findings are matched by SARIF `partialFingerprints`, **never by line number**.
- Auto-remediation only for CVSS >= 7.0 (Semgrep severity needs a documented mapping); lower severities are only reported. This is the pipeline's production policy; per `docs/benchmark/decisions.md` D11 the experiments measure remediation on all 33 dataset cases (CodeQL scores per rule, so only 12 cross 7.0), with the 12-case subset reported as a breakdown.
- Reflexive repair loop: max 3 attempts per vulnerability; record iteration count.
- Assistive posture: the agent opens a PR on a `fix/ai-remediation-...` branch; a human approves every merge. No runtime self-modification of the pipeline; no production deployment.

Roadmap phases (v2) — keep each step in its phase:

- Phases 1–2 (done): Juice Shop + SecBench.js dataset (33 cases, `docs/benchmark/dataset.md`), CI pipeline + unified SARIF.
- Phase 3 (weeks 2–4), agent in `scripts/ai_agent/`: 3.1 Groq key; 3.2 parser of the unified SARIF (line, rule, snippet, `codeFlows`); 3.3 CVSS >= 7.0 filter + documented Semgrep severity mapping; 3.4 taint trace injected as structured prompt context (FP decision based on the trace); 3.5 lightweight RAG (imports and related functions of the vulnerable file); 3.6 zero-shot / few-shot / CoT prompts, patch as a diff; 3.7 branch + PR. Ends with a **decision checkpoint** (full scope vs. cut-down Phases 4–5).
- Phase 4 (weeks 5–6): post-patch rescan + `npm test`, regression by fingerprints, reflexive loop (3 attempts), PR labelling/escalation. Functional-regression oracle decided in `docs/benchmark/decisions.md` D9 (Juice Shop API tests; per-package suite T1; differential vs. the original vulnerable version T2; oracle inputs pre-registered before any Phase 5 patch), implemented in 4.8.
- Phase 5 (weeks 7–8): within-subject experiments (FPR, RSR, overhead, regression, convergence), "blind" memorization control without the trace, Friedman/Wilcoxon. Protocol frozen in D12 (framed as research questions PI1–PI5, not hypotheses): triage 83 findings × 9 cells × 3 passes, remediation 33 cases × 6 conditions × 3 passes; runner `scripts/ai_agent/phase5.py`, analysis `phase5_analysis.py` (selftested on simulated data). Official runs need the tag `phase5-protocol` and refuse changes to `scripts/ai_agent/`, `benchmarks/` or `experiments/phase5/input/` since it — any agent change after the freeze means repeating the affected conditions.
- Phase 6 (weeks 9–14): thesis and defense.

## Repository layout

Some top-level directories are still placeholders for later phases:

- `.github/workflows/devsecops-pipeline.yml` — CI pipeline (Phase 2): Semgrep, CodeQL, Trivy (lockfiles + Juice Shop image) and TruffleHog in parallel, then `unify` merges them into `unified/findings.sarif` (one SARIF run per job, plus a line-independent `partialFingerprints["tfmContextHash/v1"]` on every result). Design and security decisions: `docs/architecture/pipeline.md`. Actions are pinned by commit SHA and scanner images by digest — keep it that way when bumping versions. No job uses secrets (fork PRs behave the same); the Phase 3 agent must not run on `pull_request_target`. Pushing workflow files needs a token with the `workflow` scope. Only root workflows run; Juice Shop's own `.github/` is inert. Default `GITHUB_TOKEN` is read-only at repo level — grant write permissions per-job in the workflow. For the agent to open PRs (Phase 3), the repo setting "Allow GitHub Actions to create and approve pull requests" must also be enabled (currently off on purpose). Dependabot security updates are deliberately disabled so they don't "fix" the benchmark's vulnerable dependencies.
- `scripts/ai_agent/` — the agent (Phases 3–5): SARIF parser, triage, remediation, reflexive loop, D9 oracles, `run_dataset.py` (4.10), `phase5.py` / `phase5_analysis.py` (Phase 5). See its README.
- `experiments/phase5/` — versioned Phase 5 input (`input/findings.sarif.gz` + `MANIFEST.json`, the CI SARIF reduced to the experiment's findings; the CI artifact expires after 30 days) and logs (`<experiment>-p<rep>.jsonl`). Unlike `results/`, it is tracked by git.
- `infra/k8s/` — Kubernetes manifests for deployment. Empty.
- `scripts/pipeline/` — CI helpers: `unify_results.py` (Phase 2.6 unified artifact) and TruffleHog's exclude list.
- `docs/architecture/` — architecture documentation (`pipeline.md`).
- `docs/benchmark/dataset.md` — methodology of the experimental dataset (sources, selection criteria C1–C8, funnel numbers, limitations). The final evaluation set is `benchmarks/dataset.csv` (cases with a complete CodeQL taint trace). Keep both in sync when the dataset changes.
- `src/app/` — the **deliberately vulnerable benchmark target** the pipeline is evaluated against.
- `benchmarks/` — experimental dataset data (see `benchmarks/README.md`): Juice Shop inventory and the SecBench.js subset. `benchmarks/secbench-js/cases/*/*/src/` is vendored, intentionally vulnerable npm package code (same rules as Juice Shop: don't fix, excluded from pre-commit). SecBench.js has no license, so its exploits are **not** vendored — the Docker harness in `benchmarks/secbench-js/harness/` fetches them from a pinned commit.
- `scripts/benchmarks/` — Python scripts that build the dataset (catalog → select → verify → materialize → detect → build_manifest; `juiceshop_detect.py` for Juice Shop). C7/C8 are computed from the pipeline's unified SARIF artifact. Each script documents its usage in its docstring.

### The benchmark target (`src/app/`)

- `src/app/juice-shop/` is OWASP Juice Shop **vendored** (no nested `.git`), pinned to v20.2.0, upstream commit `1618a611b173b4bf114028e6e02549950606e29d`. It is the single benchmark; its `data/static/codefixes/` (vulnerable snippet + correct/incorrect fixes per challenge) is usable as remediation ground truth.
- Unlike upstream, `package-lock.json` (root and `frontend/`) is committed and the upstream `.npmrc` files with `package-lock=false` were removed, so dependency versions (and Trivy SCA results) are reproducible. Use `npm ci` in CI. The frontend `sbom` script was also patched to read `dist/frontend/browser-stats.json` (Angular 22 no longer writes `stats.json`); without it `npm install` and `docker build` fail. Both are build-tooling deviations from upstream; no vulnerable code was touched.
- It is excluded from the root pre-commit hooks and from gitleaks (`.gitleaks.toml`) because it ships intentional fake secrets and must not be reformatted. It is **not** excluded from CI scanners.
- **Vulnerabilities in the benchmark app are intentional.** Do not "fix" them unless the task is explicitly to exercise/validate remediation — they are the ground truth used to measure the pipeline. Likewise, Juice Shop's `infrastructure/` and `terraform/` are intentionally insecure and must never be used to deploy real infrastructure.

## Commands

Root-level pre-commit hooks (whitespace, EOF, YAML/JSON checks, large files, gitleaks):

```bash
pre-commit install
pre-commit run --all-files
```

Juice Shop (run inside `src/app/juice-shop/`, Node 22–26):

```bash
npm install                 # also installs & builds the Angular frontend and the server
npm start                   # runs build/app (after build)
npm run serve:dev           # tsx watch server + Angular dev server
npm run lint
npm test                    # frontend (Vitest) + server unit + API tests
npm run test:server         # server unit tests (Node built-in test runner)
npm run test:api            # API integration tests (Supertest)
npm run test:e2e            # Cypress; needs the app running
npm run rsn                 # Refactoring Safety Net — required when touching challenge code
```

Run a single server/API test file:

```bash
node --import ./test/server/helpers/test-env.mjs --import tsx --test --test-force-exit test/server/<name>.unit.test.ts
node --import ./test/api/helpers/test-env.mjs --import tsx --test --test-force-exit test/api/<name>.test.ts
```

When working inside `src/app/juice-shop/`, its own `AGENTS.md` (authoritative) and `.ai/skills/` apply — notably: code touching coding challenges must keep `data/static/codefixes/` in sync and pass `npm run rsn`; don't edit `i18n/` directly.
