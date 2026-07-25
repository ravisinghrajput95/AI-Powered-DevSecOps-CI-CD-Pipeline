# Contributing to CloudCart

CloudCart is a **deliberately vulnerable** training application. Contributions that add realistic security findings for DevSecOps pipelines are welcome.

Before opening anything, two documents decide where it goes:

- **[SECURITY.md](SECURITY.md)** — CloudCart's vulnerabilities are planted and
  in-scope reports concern the *pipeline*, not the app. Read this before
  reporting a vulnerability.
- **[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)** — applies to issues, PRs and
  discussions.

## Guidelines

- Do not remove intentional vulnerabilities without documenting why.
- Keep `requirements-vulnerable.txt` for Docker/Snyk demos; use `requirements.txt` for local installs.
- Never commit real API keys or production credentials.
- Test locally with `docker compose up`, or follow the platform-specific
  [Quick Start](README.md#quick-start-docker-compose) in the README — it covers
  macOS/Linux and Windows. (The `.ps1` helper scripts are Windows-only.)

## Setup

Run the one-time [repo setup](README.md#0-repo-setup-one-time) before your first
commit — `npm install` at the root is what activates the pre-commit hooks, and
`backend/requirements-dev.txt` provides the formatters those hooks run.

## Pull requests

1. Fork and branch from `main`.
2. Ensure CI workflows pass (or document expected failures for training scans).
3. Update `README.md` if you add features or vulnerability classes.
4. If you change `scripts/` or `tests/`, run `python3 -m pytest tests/` — the
   pre-commit hook runs it automatically when those paths are staged.

Install `pip install -r tests/requirements.txt` first. Without PyYAML the 17
workflow-invariant guards **skip** rather than fail, and a skipped guard reads
the same as a passing one in CI output.

`main` is protected: `Run automated test suite` and the CodeQL analyses must
pass before a PR merges.

The PR template's checklist for `.github/workflows/` is not boilerplate — every
item on it was a real defect that shipped a green check over incomplete data
(a scan status read from a `continue-on-error` job result, a scanner-side
severity threshold that discarded 1,341 findings, an action pinned to a mutable
tag). `tests/test_workflow_invariants.py` guards each one; the checklist covers
the cases it can't yet.
