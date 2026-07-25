# Contributing to CloudCart

CloudCart is a **deliberately vulnerable** training application. Contributions that add realistic security findings for DevSecOps pipelines are welcome.

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
