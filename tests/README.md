# Test Suite

507 tests, ~1.6s. Runs automatically in CI on every push/PR touching
`scripts/` or `tests/` (see `.github/workflows/tests.yaml`).

## Structure

```
tests/
  conftest.py                          shared fixtures (loads golden + real-world data)
  fixtures/
    golden/                            synthetic, generated THROUGH the real pipeline
      build_golden_dataset.py          generator for the 8 ReleaseContext scenarios
      build_golden_executive_reports.py generator for the matching ExecutiveReports
      *.json                          the committed fixtures themselves
      executive_reports/*.json
    real_world/                        ONE frozen real CI-produced artifact pair
    snapshots/                         one literal Markdown snapshot (clean_release only)
  test_release_context_schema.py       item 1
  test_executive_report_schema.py      item 2
  test_html_renderer.py                item 3
  test_markdown_renderer.py            item 4
  test_evidence_resolution.py          item 5
  (recommendation enum rendering: covered inside html/markdown renderer tests, parametrized across all 4 values × all 8 scenarios)
  test_cross_domain_integrity.py       item 7
  test_backward_compatibility.py       item 8
  test_renderer_regression.py          item 9
  test_no_orphan_references.py        item 10 — the single highest-value module, see its docstring
```

## The 8 golden scenarios

`clean_release`, `moderate_risk_release`, `critical_release`,
`infrastructure_heavy`, `runtime_heavy`, `application_heavy`,
`container_heavy`, `mixed_domain`.

`application_heavy` and `container_heavy` matter most going forward —
every real CI run so far has had app-sec scans `SKIPPED`, so those two
domains have never once been exercised with real data. These are the
only thing standing in for that gap until a real run actually produces
that data.

`mixed_domain` deliberately encodes two correlation patterns:
a genuine cross-domain one (workload-identity-disabled + excessive-IAM,
both infrastructure, plus a kubearmor runtime finding) and a
single-domain-multi-finding one (two CVEs in the same pinned package) —
together these are what `test_cross_domain_integrity.py` checks against.

## Regenerating fixtures

**Don't, unless you mean to.** These are committed, permanent regression
fixtures — see `build_golden_dataset.py`'s docstring for why they're
generated once by hand and never regenerated automatically. If you do
need to change a scenario (e.g. to add a 9th), regenerate deliberately:

```bash
cd tests/fixtures/golden
python3 build_golden_dataset.py
python3 build_golden_executive_reports.py
```

Both generators are fully deterministic (fixed timestamps, not
`datetime.now()`) — running them twice produces byte-identical output.
CI relies on this: it regenerates fresh on every run and diffs against
the committed files, so an *unintentional* change to a pipeline function
shows up as drift, while an *intentional* one just means you commit the
regenerated fixtures along with your change.

To update the one Markdown snapshot after an intentional renderer
styling change:

```bash
UPDATE_SNAPSHOTS=1 python3 -m pytest tests/test_renderer_regression.py -k clean_release
```

## Running locally

```bash
pip install -r tests/requirements.txt
python3 -m pytest -v
```

If pip complains about an "externally managed environment" (common on
Linux distros and Homebrew Python, less common on the official macOS
python.org installer), either add `--break-system-packages` to the
command above or use a virtualenv.

If you ever see a pytest `INTERNALERROR` mentioning `jsonschema` instead
of a normal test failure, that means `jsonschema` isn't installed in
whatever Python `pytest` is actually running under — install it as
above. (A missing dependency now fails as a normal, per-file collection
error instead of crashing the whole run — but it still needs to actually
be installed.)
