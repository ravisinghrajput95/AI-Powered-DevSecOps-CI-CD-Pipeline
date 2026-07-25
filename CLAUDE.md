# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

**Read [ARCHITECTURE.md](ARCHITECTURE.md) first.** It owns the design: the
frozen four-layer separation, the normalizer → context → AI → renderer chain,
the domain model, both schemas, and `#known-gaps` — the authoritative list of
what is built versus what is only designed. This file does not repeat any of
it. What follows is only what you cannot discover by reading the code.

## Commands

```bash
# Pipeline suite — 559 tests, ~2s, no network
python3 -m pytest tests/
python3 -m pytest tests/test_workflow_invariants.py -q      # one file
python3 -m pytest tests/ -k evidence_resolution             # one pattern
pip install -r tests/requirements.txt                       # see the PyYAML trap below

cd backend && pytest --cov      # needs pip install -r requirements.txt
cd frontend && npm test

cd backend && flake8 .          # config in .flake8 / setup.cfg
cd frontend && npm run lint

python3 scripts/demo_report.py --list       # render real reports offline
python3 scripts/run_ledger.py summary       # AI run-to-run stability
```

There is no live cluster: it was destroyed and this repo's Workload Identity
binding revoked, so every GCP-dependent workflow now fails by design.
`demo_report.py` is the only way to exercise the rendering and citation path.

## Things that will bite you

**PyYAML absent means 24 guards skip, not fail.**
`tests/test_workflow_invariants.py` opens with `pytest.importorskip("yaml")`.
A skipped guard is indistinguishable from a passing one in CI summary output,
so a green run without `tests/requirements.txt` installed proves less than it
appears to.

**Do not fix CloudCart's vulnerabilities.** The SQLi in
`backend/routes/products.py`, the `dangerouslySetInnerHTML` in
`ReviewList.jsx`, the IDOR in `backend/routes/identity.py`, the planted AWS and
Stripe keys — all deliberate. `backend/tests/` and `frontend/src/__test__/`
assert several are *still present*, so "fixing" one fails the suite. See
[SECURITY.md](SECURITY.md).

**Adding a test breaks the docs build, on purpose.**
`tests/test_docs_accuracy.py` compares what pytest collects against the count
claimed in `README.md` (prose *and* the shields.io badge), `ARCHITECTURE.md`,
and this file. Update all four. The count went stale four times in one day
before the guard existed.

**A failing workflow invariant is describing a real regression.** Each of the
24 guards encodes a defect that shipped green over incomplete data — a status
read from `needs.<job>.result` (which `continue-on-error` masks) instead of the
step's own exit code, scanner-side filtering that discarded 1,341 findings, an
unpinned action, a KubeArmor capture window with nothing exercising it. All are
mutation-tested. Do not relax one to get a build through.

**No type hints anywhere.** 0 of 114 functions in `scripts/`, 0 of 53 in
`backend/`. Adding them piecemeal implies a guarantee that only sometimes
holds. The convention that does apply: every module gets a docstring explaining
*why it exists and what failure it prevents* — see
`scripts/normalizer_common.py`, `backend/routes/identity.py`,
`tests/test_workflow_invariants.py`.

**`dependabot.yml` lives at the repository root, not `.github/`.** Moving it
activates it; against an intentionally vulnerable app that is pure PR noise.
The location is a deliberate kill switch, not an oversight.

**Scrub regenerated reports before committing.** GCP project ids become
`<GCP_PROJECT_ID>`, host addresses `<CLUSTER_IP>`. A committed report once
carried a live LoadBalancer IP in 34 places while that address served the
vulnerable app on the public internet. `test_docs_accuracy.py` now fails on any
host address under `reports/`.

**KubeArmor findings are detection tests, not intrusions.** The runtime scan
execs a shell inside the app containers on purpose, to exercise its own audit
policies — the same active-probing model ZAP uses for DAST.
`scripts/system_prompt.md` states this to the model, because without it a
generated report called the pipeline's own test action "a potential active
compromise indicator".

**Collect everything, filter downstream.** Severity thresholds belong in
`build_release_context.py --container-severity-floor`, never in a scanner
invocation — filtering at the source destroys data irrecoverably, and a guard
enforces it.

## Conventions

- GitHub Actions pinned to 40-char commit SHAs, never tags.
- Helm install order: `bootstrap/` (CRDs, controllers) → `postgresql/` →
  `cloudcart/`.
- Commit messages explain in prose why the change was needed and what failure
  it prevents. Read `git log` before writing one.
