"""Guards on the request payload sent to the Anthropic API.

Nothing else in the suite touches call_claude — every other test starts from
an executive_report.json that already exists, so the request that produced it
was entirely untested. The parameters asserted here are the ones whose loss is
silent: drop `temperature` and the call still succeeds, still validates, still
renders, and only becomes visible as two runs over the same evidence
disagreeing weeks later.

urlopen is stubbed, so these make no network call and need no API key.
"""
import importlib.util
import json
import os

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "run_security_analysis.py")


def load_module():
    spec = importlib.util.spec_from_file_location("run_security_analysis", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rsa = load_module()


class FakeResponse:
    """Minimal stand-in for the urlopen context manager."""

    def __init__(self, payload):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return json.dumps(self._payload).encode("utf-8")


@pytest.fixture
def captured(monkeypatch):
    """Run call_claude against a stubbed API and return the sent payload."""
    sent = {}

    def fake_urlopen(request, timeout=None):
        sent["payload"] = json.loads(request.data.decode("utf-8"))
        sent["headers"] = dict(request.headers)
        sent["timeout"] = timeout
        return FakeResponse({
            "stop_reason": "tool_use",
            "usage": {"input_tokens": 10, "output_tokens": 20},
            "content": [{
                "type": "tool_use",
                "id": "toolu_test",
                "name": rsa.TOOL_NAME,
                "input": {"ok": True},
            }],
        })

    monkeypatch.setattr(rsa.urllib.request, "urlopen", fake_urlopen)
    rsa.call_claude(
        messages=[{"role": "user", "content": "hi"}],
        tool_schema={"type": "object"},
        system_prompt="sys",
        model="claude-sonnet-4-6",
        max_tokens=16384,
        api_key="test-key-not-real",
        timeout=600,
    )
    return sent


def test_temperature_is_pinned_low_by_default(captured):
    """The API defaults to 1.0. A release verdict must be a function of the
    evidence, not of sampling — the same context must not approve on one run
    and block on the next.

    This asserts the *default*, with no --temperature passed, because the
    failure mode is someone dropping the key from the payload rather than
    setting it wrong.
    """
    payload = captured["payload"]
    assert "temperature" in payload, (
        "temperature is absent from the request — the API will default to 1.0 and the "
        "report becomes unreproducible for the one decision it exists to support."
    )
    assert payload["temperature"] == 0.0, (
        "expected temperature 0.0 by default, got {!r}".format(payload["temperature"])
    )


def test_temperature_is_still_overridable(monkeypatch):
    """Pinned is not the same as hardcoded — raising it to observe how much
    the reasoning moves is a legitimate experiment, just not a release run."""
    sent = {}

    def fake_urlopen(request, timeout=None):
        sent["payload"] = json.loads(request.data.decode("utf-8"))
        return FakeResponse({
            "stop_reason": "tool_use",
            "content": [{"type": "tool_use", "id": "t", "name": rsa.TOOL_NAME, "input": {}}],
        })

    monkeypatch.setattr(rsa.urllib.request, "urlopen", fake_urlopen)
    rsa.call_claude([{"role": "user", "content": "hi"}], {}, "sys",
                    "claude-sonnet-4-6", 100, "k", 60, temperature=1.0)
    assert sent["payload"]["temperature"] == 1.0


def test_tool_use_is_forced(captured):
    """Structured output depends on tool_choice being pinned to the single
    tool. Without it the model may answer in prose and every downstream
    schema assumption breaks."""
    payload = captured["payload"]
    assert payload["tool_choice"] == {"type": "tool", "name": rsa.TOOL_NAME}
    assert [t["name"] for t in payload["tools"]] == [rsa.TOOL_NAME], (
        "exactly one tool should be offered; a second gives the model a choice it "
        "should not have"
    )


def test_api_key_travels_in_the_header_not_the_body(captured):
    """A key in the payload would be echoed into any logged request body."""
    assert "test-key-not-real" not in json.dumps(captured["payload"])
    header_values = " ".join(str(v) for v in captured["headers"].values())
    assert "test-key-not-real" in header_values
