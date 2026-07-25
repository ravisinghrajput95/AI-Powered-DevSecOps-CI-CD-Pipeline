# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repository is

An AI-powered DevSecOps pipeline. Nine security scanners feed one canonical
`ReleaseContext`, an AI agent reasons over it under strict constraints, and the
output is a cited, schema-validated release recommendation.

**CloudCart** — the React/Flask/Postgres app in `frontend/`, `backend/` — is
not the product. It is the deliberately vulnerable fixture the pipeline scans.
Read `ARCHITECTURE.md` before changing anything under `scripts/`.

## Commands

```bash
# Pipeline test suite (the main one — 559 tests, ~2s, no network)
python3 -m pytest tests/
python3 -m pytest tests/test_workflow_invariants.py -q      # one file
python3 -m pytest tests/ -k evidence_resolution             # one pattern
pip install -r tests/requirements.txt                       # PyYAML is REQUIRED, see below

# CloudCart's own suites
cd backend && pytest --cov          # needs pip install -r requirements.txt
cd frontend && npm test             # jest

# Lint
cd backend && flake8 .              # config in .flake8 / setup.cfg
cd frontend && npm run lint

# Render a real report offline — no cluster, no API key, no network
python3 scripts/demo_report.py --list
python3 scripts/demo_report.py --scenario critical_release

# Run-to-run stability across recorded AI runs
python3 scripts/run_ledger.py summary
```

`tests/requirements.txt` must be installed before trusting a green run:
`test_workflow_invariants.py` guards with `pytest.importorskip("yaml")`, so
without PyYAML its 24 guards **skip** rather than fail, and a skipped guard is
indistinguishable from a passing one.

Local runs of the pipeline against a live cluster are not possible right now —
the GKE cluster was torn down and this repo's Workload Identity binding
revoked. `demo_report.py` exists so the rendering and citation path stays
exercisable without any of that.

## Architecture

### The frozen separation

Four layers, and the boundaries are the design:

1. **Security tools own facts.** A finding's severity, category and existence
   come from a real scanner. Never inferred, never invented.
2. **Python owns deterministic computation.** Domain assignment, occurrence
   counting, statistics — anything with one correct answer given the input.
3. **AI owns reasoning only.** Correlation, prioritisation, the
   recommendation. It never invents a finding, never changes a severity, and
   cites every claim by `finding_id`.
4. **Humans own the deploy decision.** The output is a recommendation with
   evidence, not a gate that fires by itself.

Moving work across those lines is the one change that needs a deliberate
decision rather than a commit.

### The artifact chain

```
normalize_*.py          per-tool raw output -> canonical Finding
   |
build_release_context.py    app + runtime findings   (804 LOC, main() is 183)
build_infra_context.py      infra + terraform findings
   |
compose_release_context.py  merge, assign_domain, statistics
   -> final_release_context.json      (ReleaseContext v1.0, FROZEN)
   |
run_security_analysis.py    Claude, forced tool-use, temperature 0
   -> executive_report.json           (ExecutiveReport v1.0, FROZEN)
   |
render_report.py / render_html_report.py
   ReleaseContext resolves the finding_id citations at render time
```

Both schemas are **importable Python** (`scripts/release_context_schema.py`,
`scripts/executive_report_schema.py`), not committed `.schema.json` files, so
producers and consumers share one source of truth and the tool's `input_schema`
is derived at runtime. Frozen means field additions need an explicit decision.

`ExecutiveReport` does not record which model produced it. That is a known
auditability gap; callers pass the model explicitly (see `run_ledger.py`).

### Scan status is a five-value fact

`SUCCESS` / `FAILED` / `SKIPPED` / `NOT_CONFIGURED` / `NO_SIGNAL`.

`NO_SIGNAL` means the tool ran to completion and produced nothing usable — the
domain is **unmeasured, not clean**. Most of this repository's hard-won
correctness lives in keeping those five distinct. A tool that fails auth must
never look like a clean scan.

## Things that will bite you

**Do not fix CloudCart's vulnerabilities.** The SQLi in
`backend/routes/products.py`, the `dangerouslySetInnerHTML` in
`ReviewList.jsx`, the IDOR in `backend/routes/identity.py`, the planted AWS and
Stripe keys — all deliberate, and `backend/tests/` and
`frontend/src/__test__/` assert several are *still present*. `SECURITY.md` is
the contract.

**Adding a test breaks the docs build.** `tests/test_docs_accuracy.py` compares
what pytest collects against the count claimed in `README.md` (prose and the
shields.io badge), `ARCHITECTURE.md`, and this file. Add a test, update all
four. This is deliberate friction — the count went stale four times in one day
before the guard existed, and a number a reader can check and find wrong
discredits the numbers they cannot check.

**Workflow changes need `tests/test_workflow_invariants.py` to pass.** Its 24
guards each encode a defect that shipped green over incomplete data: a scan
status read from `needs.<job>.result` (which `continue-on-error` masks) rather
than the step's own exit code, scanner-side severity filtering that discarded
1,341 findings, an unpinned action, a KubeArmor capture window with nothing
exercising it. Every guard is mutation-tested. If one fails, it is describing a
real regression.

**No type hints.** 0 of 114 functions in `scripts/`, 0 of 53 in `backend/`. Do
not add them piecemeal — a half-annotated tree implies a guarantee that only
sometimes holds. The convention that does apply: every module gets a docstring
explaining *why it exists and what failure it prevents*.
`scripts/normalizer_common.py`, `backend/routes/identity.py` and
`tests/test_workflow_invariants.py` are the reference examples. Comments earn
their place by explaining a decision or a bug, never by restating the code.

**`dependabot.yml` belongs at the repository root, not in `.github/`.** Moving
it activates it; the app is intentionally vulnerable and the resulting PR
volume is noise. Its placement is a deliberate kill switch.

**Committed reports must not leak infrastructure.** A live LoadBalancer IP was
published in `reports/sample/` in 34 places while serving a vulnerable app on
the public internet. `test_docs_accuracy.py` now fails on any host address in
`reports/`. Scrub GCP project ids to `<GCP_PROJECT_ID>` and addresses to
`<CLUSTER_IP>` before committing a regenerated report.

**KubeArmor findings are detection tests, not intrusions.** The runtime scan
execs a shell in the app containers on purpose to exercise its own audit
policies — the same active-probing model ZAP uses. `scripts/system_prompt.md`
tells the model this, because without it a report described the pipeline's own
test action as "a potential active compromise indicator".

## Deploys

`helm upgrade --install` from `deploy-backend.yaml` / `deploy-frontend.yaml`.
**ArgoCD is not implemented** — no workflow references it. Jira, Slack, the AI
Remediation Agent and Falco are likewise designed but unbuilt.
`ARCHITECTURE.md#known-gaps` is the authoritative list of what exists versus
what is aspiration; keep it accurate rather than quietly building around it.

## Conventions worth matching

- Actions pinned to 40-char commit SHAs, never tags.
- Collect everything, filter downstream. Severity thresholds belong in
  `build_release_context.py --container-severity-floor`, never in a scanner.
- Helm charts install in order: `bootstrap/` (CRDs, controllers) →
  `postgresql/` → `cloudcart/`.
- Commit messages explain why the change was needed and what failure it
  prevents, in prose. Look at `git log` before writing one.
