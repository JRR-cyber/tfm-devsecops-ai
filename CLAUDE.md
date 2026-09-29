# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project purpose

Master's thesis (TFM, UC3M) project: a Shift-Left DevSecOps pipeline with a **hybrid architecture** — symbolic reachability analysis (dataflow/taint traces) + contextual LLM decisions — for triage and assisted remediation of vulnerabilities. Project docs (README, SECURITY.md) are in Spanish.

Fixed design decisions (roadmap v2 — don't substitute tools without being asked):

- Scanners: Semgrep OSS (SAST), Trivy (SCA + container), TruffleHog (secrets), CodeQL (dataflow/taint `codeFlows`). All output SARIF/JSON, consolidated into one unified artifact that feeds the agent.
- LLM: Groq API, Llama 3.3 70B as the single model (secret `GROQ_API_KEY`). Experiments compare **prompting strategies** (zero-shot / few-shot / CoT), not models.
- Pre/post-patch findings are matched by SARIF `partialFingerprints`, **never by line number**.
- Auto-remediation only for CVSS >= 7.0 (Semgrep severity needs a documented mapping); lower severities are only reported.
- Reflexive repair loop: max 3 attempts per vulnerability; record iteration count.
- Assistive posture: the agent opens a PR on a `fix/ai-remediation-...` branch; a human approves every merge. No runtime self-modification of the pipeline; no production deployment.

## Repository layout

The repo is at an early scaffolding stage — most top-level directories are empty placeholders for planned components:

- `.github/workflows/` — CI pipeline (`devsecops-pipeline.yml`: scanners → unified SARIF → AI agent). Empty. Only root workflows run; Juice Shop's own `.github/` is inert. Default `GITHUB_TOKEN` is read-only at repo level — grant write permissions per-job in the workflow. For the agent to open PRs (Phase 3), the repo setting "Allow GitHub Actions to create and approve pull requests" must also be enabled (currently off on purpose). Dependabot security updates are deliberately disabled so they don't "fix" the benchmark's vulnerable dependencies.
- `scripts/ai_agent/` — Python orchestrator (`triage_engine.py`) that parses SARIF, triages findings and proposes fixes. Empty.
- `infra/k8s/` — Kubernetes manifests for deployment. Empty.
- `docs/architecture/` — architecture documentation. Empty.
- `src/app/` — the **deliberately vulnerable benchmark target** the pipeline is evaluated against.

### The benchmark target (`src/app/`)

- `src/app/juice-shop/` is OWASP Juice Shop **vendored** (no nested `.git`), pinned to v20.2.0, upstream commit `1618a611b173b4bf114028e6e02549950606e29d`. It is the single benchmark; its `data/static/codefixes/` (vulnerable snippet + correct/incorrect fixes per challenge) is usable as remediation ground truth.
- Unlike upstream, `package-lock.json` (root and `frontend/`) is committed and the upstream `.npmrc` files with `package-lock=false` were removed, so dependency versions (and Trivy SCA results) are reproducible. Use `npm ci` in CI. Known issue: with the locked Angular 22.2.0, the frontend `sbom` step fails (looks for `dist/frontend/stats.json`, Angular writes `browser-stats.json`) — it doesn't affect the app or tests.
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
