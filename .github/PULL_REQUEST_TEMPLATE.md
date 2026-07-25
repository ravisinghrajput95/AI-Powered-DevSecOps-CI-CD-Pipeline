<!--
Thanks for contributing. Delete any section that doesn't apply — a short PR
with two relevant lines beats a fully-filled template.
-->

## What this changes

<!-- One or two sentences. -->

## Why

<!--
For a bug fix: what was reported vs. what was actually true.
For a feature: what the pipeline can now conclude that it couldn't before.
-->

---

## Checks

- [ ] `pytest tests/` passes locally (`pip install -r tests/requirements.txt` first — PyYAML is required, or 17 workflow guards **skip** instead of running)
- [ ] I did not remove or "fix" any of CloudCart's [intentional vulnerabilities](../#intentional-vulnerabilities)
- [ ] No real credentials, project IDs, cluster IPs or hostnames in code, fixtures or committed reports

### If this touches `.github/workflows/`

- [ ] New action references are pinned to a **40-char commit SHA**, not a tag
- [ ] No scanner-side severity filtering — collect everything, filter in `build_release_context.py`
- [ ] A scan status is derived from the step's own exit code (`outputs.completed`), never `needs.<job>.result`, which `continue-on-error` masks
- [ ] `tests/test_workflow_invariants.py` still passes

<!--
That last group exists because every item in it was a real defect that shipped
green over incomplete data. The guards catch a revert; the checklist is for the
cases they don't cover yet.
-->

### If this touches `scripts/`

- [ ] Schema changes went into `release_context_schema.py` / `executive_report_schema.py` — the tool `input_schema` derives from them at runtime, so editing a prompt's schema by hand will drift
- [ ] A new field is reflected in both the Markdown and HTML renderers
- [ ] Added a fixture under `tests/fixtures/` if this changes how findings are parsed or normalized

### If this changes AI behaviour

- [ ] The model still cannot assert anything absent from the release context
- [ ] Ran at least once against real data and attached the verdict, or explained why not (API cost is a legitimate reason)
