# Contributing to CloudCart

CloudCart is a **deliberately vulnerable** training application. Contributions that add realistic security findings for DevSecOps pipelines are welcome.

## Guidelines

- Do not remove intentional vulnerabilities without documenting why.
- Keep `requirements-vulnerable.txt` for Docker/Snyk demos; use `requirements.txt` for local installs.
- Never commit real API keys or production credentials.
- Test locally: `docker compose up` or `scripts/start-local.ps1` + `backend/run-backend.ps1` + `npm run dev`.

## Pull requests

1. Fork and branch from `main`.
2. Ensure CI workflows pass (or document expected failures for training scans).
3. Update `README.md` if you add features or vulnerability classes.
