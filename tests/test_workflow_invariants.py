"""Structural invariants for the security workflows.

Every defect this file guards was real, shipped, and produced a green CI
check over incomplete data. None of them raised an error; each was found
only by comparing numbers end to end. The existing suite covers scripts/
thoroughly and nothing covered workflow logic, so a revert of any fix below
would silently restore the original behaviour.

These are deliberately structural, not behavioural — they parse the YAML and
assert properties, rather than executing workflows. That catches the exact
regressions seen on 2026-07-25 (a status derived from the wrong source, a
swallowed exit code, a reintroduced scanner-side filter) without needing a
runner, credentials, or a cluster.

Each test names the failure it exists to prevent.
"""
import glob
import os
import re

import pytest

yaml = pytest.importorskip(
    "yaml", reason="PyYAML required to parse workflows — pip install -r tests/requirements.txt"
)

WORKFLOW_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".github", "workflows"
)


def load_workflow(name):
    with open(os.path.join(WORKFLOW_DIR, name)) as f:
        return yaml.safe_load(f)


def workflow_text(name):
    with open(os.path.join(WORKFLOW_DIR, name)) as f:
        return f.read()


APP_SEC_WORKFLOWS = ["app-security-scan-backend.yaml", "app-security-scan-frontend.yaml"]
CI_WORKFLOWS = ["backend-ci.yaml", "frontend-ci.yaml"]


# ── Silent zero #1: a scanner that fails auth must not look clean ──────────

@pytest.mark.parametrize("wf", APP_SEC_WORKFLOWS)
def test_gitguardian_status_comes_from_step_output_not_job_result(wf):
    """An expired GITGUARDIAN_API_KEY was recorded as a successful scan.

    The job carries continue-on-error: true, so needs.<job>.result reads
    "success" no matter what happened inside it. The status must come from
    the step's captured exit code instead.
    """
    doc = load_workflow(wf)
    job = doc["jobs"]["gitguardian-scan"]
    assert job.get("outputs", {}).get("completed"), (
        f"{wf}: gitguardian-scan must expose a 'completed' output; without it the "
        "recorded status falls back to the job result, which continue-on-error masks."
    )
    text = workflow_text(wf)
    assert "needs.gitguardian-scan.outputs.completed" in text, (
        f"{wf}: GitGuardian status must be derived from outputs.completed, "
        "not needs.gitguardian-scan.result."
    )


@pytest.mark.parametrize("wf", APP_SEC_WORKFLOWS)
def test_ggshield_exit_code_is_not_swallowed(wf):
    """`ggshield ... --json > file || true` discarded the auth failure.

    With `|| true` the step always succeeds, the empty output normalises to
    [], and a broken secrets scanner is indistinguishable from a clean repo.
    """
    text = workflow_text(wf)
    assert "ggshield secret scan repo . --all-secrets --json > gitguardian-findings.json || true" not in text, (
        f"{wf}: ggshield's exit code must be captured, not discarded with '|| true'."
    )
    assert "exit_code=$?" in text, f"{wf}: expected an explicit exit-code capture around ggshield."


@pytest.mark.parametrize("wf", APP_SEC_WORKFLOWS)
def test_snyk_sca_status_comes_from_step_output(wf):
    """Snyk SCA captured its exit code but reported the job result instead.

    The case block always exits 0, so the job read "success" whether the scan
    ran or failed authentication.
    """
    component = "backend" if "backend" in wf else "frontend"
    doc = load_workflow(wf)
    job = doc["jobs"][f"snyk-sca-{component}"]
    assert job.get("outputs", {}).get("completed"), (
        f"{wf}: snyk-sca-{component} must expose a 'completed' output."
    )
    assert f"needs.snyk-sca-{component}.outputs.completed" in workflow_text(wf), (
        f"{wf}: Snyk SCA status must derive from the step's exit code."
    )


# ── Silent zero #2: filtering belongs downstream, not in the scanner ───────

@pytest.mark.parametrize("wf", CI_WORKFLOWS)
def test_container_scan_has_no_severity_threshold(wf):
    """--severity-threshold=critical hid 182 real vulnerabilities.

    The frontend image reported "No known operating system vulnerabilities"
    while Snyk's own output in the same report listed 182 (0 critical, 15
    high, 6 medium, 161 low). Filtering at the scanner destroys data
    irrecoverably; significance is decided by build_release_context.py's
    --container-severity-floor, which can change without re-running scans.
    """
    for line in workflow_text(wf).splitlines():
        stripped = line.strip()
        if stripped.startswith("--severity-threshold"):
            pytest.fail(
                f"{wf}: scanner-side --severity-threshold reintroduced ({stripped!r}). "
                "Filter in build_release_context.py instead so the artifact stays complete."
            )


# ── Silent zero #3: a tool that runs must not report as unconfigured ───────

@pytest.mark.parametrize("wf", CI_WORKFLOWS)
def test_syft_status_is_recorded_after_the_sbom_is_generated(wf):
    """syft was reported NOT_CONFIGURED while producing a ~400KB SBOM.

    The first fix then recorded FAILED, because the status step ran one
    second BEFORE the step that creates the file it checks. Ordering is the
    invariant worth pinning.
    """
    doc = load_workflow(wf)
    names = [s.get("name", "") for s in doc["jobs"]["docker"]["steps"]]
    assert "Generate SBOM with Syft" in names, f"{wf}: SBOM step missing"
    assert "Record scan status" in names, f"{wf}: scan-status step missing"
    assert names.index("Record scan status") > names.index("Generate SBOM with Syft"), (
        f"{wf}: 'Record scan status' must run AFTER 'Generate SBOM with Syft' — it "
        "verifies the SPDX file exists, and previously ran first, recording FAILED "
        "on every build."
    )
    assert '"syft"' in workflow_text(wf), f"{wf}: syft status is not recorded at all."


# ── Deploy safety ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("wf", ["deploy-backend.yaml", "deploy-frontend.yaml"])
def test_deploy_is_gated_on_push_or_dispatch_from_main(wf):
    """workflow_run fires for PR-triggered CI too.

    Without event/head_branch guards a green PR build deploys unmerged code
    to the cluster.
    """
    condition = " ".join(str(load_workflow(wf)["jobs"]["deploy"]["if"]).split())
    for expected in ("conclusion == 'success'", "head_branch == 'main'", "event == 'push'"):
        assert expected in condition, f"{wf}: deploy guard is missing `{expected}`"
    assert "pull_request" not in condition, (
        f"{wf}: pull_request must never reach the deploy job."
    )


@pytest.mark.parametrize("wf", ["deploy-backend.yaml", "deploy-frontend.yaml"])
def test_atomic_is_not_unconditional(wf):
    """--atomic UNINSTALLS on a first install rather than rolling back.

    It deleted the failed pods and events that explained a hung post-install
    hook, leaving nothing to debug.
    """
    text = workflow_text(wf)
    assert "$ATOMIC" in text, f"{wf}: --atomic must be conditional on an existing release."
    for line in text.splitlines():
        if line.strip() == "--atomic \\":
            pytest.fail(f"{wf}: unconditional --atomic reintroduced.")


# ── DAST target must not be a hardcoded, cluster-specific IP ───────────────

@pytest.mark.parametrize("wf", ["runtime-security-scan.yaml", "dast.yaml"])
def test_dast_target_is_resolved_at_runtime(wf):
    """A hardcoded LoadBalancer IP went stale on every cluster rebuild.

    ZAP timed out against a dead address, which failed the whole run — and
    because release-readiness filters upstream sources on --status=success,
    the entire runtime domain (Kyverno and KubeArmor included) vanished from
    the report.
    """
    doc = load_workflow(wf)
    assert "resolve-target" in doc["jobs"], f"{wf}: resolve-target job missing."
    default = doc[True]["workflow_dispatch"]["inputs"]["target_url"].get("default", "")
    assert default == "", (
        f"{wf}: target_url default must be empty so the live Service is resolved; "
        f"found a hardcoded {default!r}."
    )
    assert "needs.resolve-target.outputs.target_url" in workflow_text(wf), (
        f"{wf}: the ZAP job must consume the resolved target."
    )


# ── Supply chain ──────────────────────────────────────────────────────────

def test_all_actions_are_sha_pinned():
    """A mutable tag can be repointed by whoever controls the action's repo.

    These run with GCP Workload Identity and every scanner token in the repo;
    snyk/actions/setup was pinned to @master before 2026-07-25.
    """
    import re

    unpinned = []
    pattern = re.compile(r"uses:\s*'?([A-Za-z0-9._/-]+)@([A-Za-z0-9._-]+)'?")
    for path in sorted(glob.glob(os.path.join(WORKFLOW_DIR, "*.y*ml"))):
        with open(path) as f:
            for lineno, line in enumerate(f, 1):
                m = pattern.search(line)
                if m and not re.fullmatch(r"[a-f0-9]{40}", m.group(2)):
                    unpinned.append(f"{os.path.basename(path)}:{lineno} {m.group(1)}@{m.group(2)}")
    assert not unpinned, "Unpinned action references:\n  " + "\n  ".join(unpinned)


# ── Silent zero #4: a capture window nobody gives anything to capture ──────

RUNTIME_WF = "runtime-security-scan.yaml"
EXERCISE_SCRIPT = ".github/scripts/exercise-kubearmor-policies.sh"


def capture_step():
    """The KubeArmor capture step, located by id rather than name so a
    rewording of the display name doesn't silently skip these guards."""
    doc = load_workflow(RUNTIME_WF)
    steps = doc["jobs"]["kubearmor-live-scan"]["steps"]
    for step in steps:
        if step.get("id") == "kubearmor_run":
            return step
    pytest.fail(f"{RUNTIME_WF}: no step with id 'kubearmor_run' — the capture step was renamed or removed")


def test_the_exercise_script_exists_and_is_invoked_by_the_capture_step():
    """KubeArmor records only what happens while its window is open.

    CloudCart in steady state serves HTTP and never execs a shell, reads
    /etc/shadow or runs curl — so before this script existed every window
    closed empty and the runtime domain reported NO_SIGNAL on every run. That
    was misread for months as an upstream containerd defect; the tool was
    fine and the window was idle.

    Delete the invocation and nothing fails: karmor still runs the full
    window, still exits 124 as designed, still writes a valid (empty) file.
    The domain just silently goes unmeasured again.
    """
    script_path = os.path.join(os.path.dirname(WORKFLOW_DIR), "scripts",
                               "exercise-kubearmor-policies.sh")
    assert os.path.exists(script_path), (
        f"{EXERCISE_SCRIPT} is missing — without it the capture window has nothing "
        "to record and the runtime domain reverts to NO_SIGNAL."
    )
    assert "exercise-kubearmor-policies.sh" in str(capture_step().get("run", "")), (
        f"{RUNTIME_WF}: the capture step must invoke {EXERCISE_SCRIPT}."
    )


def test_the_exercise_runs_inside_the_capture_window():
    """Ordering is the whole mechanism, and it is invisible when wrong.

    karmor must be backgrounded first, the exercise run while it streams, and
    the capture waited on afterwards. Run the exercise before karmor starts,
    or after it has exited, and every alert is generated with nothing
    listening — producing exactly the empty capture this step exists to
    prevent, with no error anywhere.
    """
    run = str(capture_step().get("run", ""))
    backgrounded = re.search(r"timeout .*karmor logs .*&\s*$", run, re.MULTILINE)
    assert backgrounded, (
        f"{RUNTIME_WF}: karmor logs must be backgrounded (trailing &) so the exercise "
        "can run while the stream is open."
    )
    pos_karmor = run.index("karmor logs")
    pos_exercise = run.index("exercise-kubearmor-policies.sh")
    pos_wait = run.index("wait ")
    assert pos_karmor < pos_exercise < pos_wait, (
        f"{RUNTIME_WF}: expected order is karmor(background) -> exercise -> wait; "
        f"got positions karmor={pos_karmor}, exercise={pos_exercise}, wait={pos_wait}."
    )


def test_the_stream_is_given_time_to_establish_before_events_are_generated():
    """Events fired before the gRPC stream is up are lost, not queued.

    Observed directly while building this: a capture with no settle time
    returned zero alerts for actions that were definitely performed.
    """
    run = str(capture_step().get("run", ""))
    between = run[run.index("karmor logs"):run.index("exercise-kubearmor-policies.sh")]
    sleeps = [int(m) for m in re.findall(r"sleep\s+(\d+)", between)]
    assert sleeps and max(sleeps) >= 5, (
        f"{RUNTIME_WF}: expected a settle sleep of >=5s between starting karmor and "
        f"generating events; found {sleeps or 'none'}."
    )


def test_capture_window_is_long_enough_for_setup_exercise_and_propagation():
    """CAPTURE_SECONDS covers three things in sequence, not one.

    At its original 30s — chosen when the window was passive — the ~10s
    settle plus the exercise left almost nothing for alerts to propagate
    daemonset -> relay -> client. A too-short window fails by returning
    fewer findings, never by erroring.
    """
    doc = load_workflow(RUNTIME_WF)
    seconds = int(doc["jobs"]["kubearmor-live-scan"]["env"]["CAPTURE_SECONDS"])
    run = str(capture_step().get("run", ""))
    settle = max([int(m) for m in re.findall(r"sleep\s+(\d+)", run)] or [0])
    assert seconds >= settle + 30, (
        f"{RUNTIME_WF}: CAPTURE_SECONDS={seconds} leaves only {seconds - settle}s after "
        f"a {settle}s settle for the exercise and alert propagation. Expected at least "
        f"{settle + 30}."
    )


def test_kubearmor_status_is_derived_from_findings_not_from_the_job_result():
    """The one silent zero an exit code cannot catch.

    karmor exits 124 by design whether it captured 200 alerts or none, so the
    status has to come from whether normalized-kubearmor.json actually holds
    findings. Reporting SUCCESS on an empty set tells the model "runtime
    scanned, nothing found" — i.e. clean — when the truth is unmeasured.
    """
    text = workflow_text(RUNTIME_WF)
    assert "no_signal" in text, (
        f"{RUNTIME_WF}: NO_SIGNAL must remain reachable — it is the honest status for a "
        "window that genuinely captured nothing."
    )
    assert "normalized-kubearmor.json" in text, (
        f"{RUNTIME_WF}: the recorded status must be derived from the normalized findings "
        "file, not from the job's result."
    )


def test_the_exercise_script_is_syntactically_valid():
    """`bash -n` on a script nothing else parses until it runs.

    It is invoked from a workflow step rather than imported, so a syntax
    error would first surface mid-capture on a real runner against a real
    cluster — and, because the step tolerates exercise failure to avoid
    breaking the scan, it would degrade to an empty window rather than a
    loud error.
    """
    import shutil
    import subprocess

    bash = shutil.which("bash")
    if not bash:
        pytest.skip("bash not available")
    script = os.path.join(os.path.dirname(WORKFLOW_DIR), "scripts",
                          "exercise-kubearmor-policies.sh")
    proc = subprocess.run([bash, "-n", script], capture_output=True, text=True)
    assert proc.returncode == 0, f"{EXERCISE_SCRIPT} has a syntax error:\n{proc.stderr}"


# ── The stability ledger must keep being fed ──────────────────────────────

def test_release_readiness_records_every_ai_run_in_the_ledger():
    """A stability history only exists if every real run contributes to it.

    Drop this step and nothing breaks: the report still renders, the artifact
    still uploads, and the ledger simply stops growing — so the one question
    people ask about an LLM in a release gate quietly becomes unanswerable
    again. The failure is invisible precisely because the ledger's value is
    cumulative.
    """
    doc = load_workflow("release-readiness.yaml")
    steps = doc["jobs"]["assess"]["steps"]
    names = [s.get("name", "") for s in steps]

    ledger_steps = [s for s in steps if "run_ledger.py" in str(s.get("run", ""))]
    assert ledger_steps, (
        "release-readiness.yaml no longer records runs via scripts/run_ledger.py — "
        "the stability history will stop growing without any test failing."
    )
    step = ledger_steps[0]

    # The model is not recorded in ExecutiveReport v1.0, so it must be passed
    # explicitly or rows become uncomparable across models.
    assert "--model" in str(step.get("run", "")), (
        "the ledger step must pass --model; ExecutiveReport does not record it and "
        "rows from different models would otherwise be compared as equivalent."
    )

    # It reads the rendered run's artifacts, so it has to come after they exist.
    idx = steps.index(step)
    for produced_by in ("Run AI Security Analysis", "Build ReleaseContext"):
        matching = [i for i, n in enumerate(names) if produced_by.lower() in n.lower()]
        if matching:
            assert idx > matching[0], (
                f"the ledger step must run after '{names[matching[0]]}', which produces "
                "the files it reads."
            )
