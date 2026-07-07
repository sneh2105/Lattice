# -*- coding: utf-8 -*-
"""Tests for fingerprint-based drift detection between two scans."""
import pytest
import tempfile
import shutil
from pathlib import Path


@pytest.fixture(autouse=True)
def isolated_baseline_dir(monkeypatch):
    tmp_dir = tempfile.mkdtemp()
    import agentscan.drift as drift
    monkeypatch.setattr(drift, "_BASELINE_DIR", Path(tmp_dir))
    yield
    shutil.rmtree(tmp_dir, ignore_errors=True)


def _finding(fid, severity, tags=None):
    return {"id": fid, "title": "Test: " + fid, "severity": severity, "tags": tags or []}


def test_no_baseline_returns_has_baseline_false():
    from agentscan.drift import compute_drift
    result = compute_drift("some/target.yaml", [_finding("F1", "HIGH")])
    assert result["has_baseline"] is False


def test_save_and_load_baseline():
    from agentscan.drift import save_baseline, load_baseline
    save_baseline("t.yaml", [_finding("F1", "HIGH")])
    loaded = load_baseline("t.yaml")
    assert loaded is not None
    assert len(loaded["findings"]) == 1


def test_new_finding_detected():
    from agentscan.drift import save_baseline, compute_drift
    save_baseline("t.yaml", [_finding("F1", "HIGH")])
    drift = compute_drift("t.yaml", [_finding("F1", "HIGH"), _finding("F2", "CRITICAL")])
    assert drift["has_baseline"] is True
    assert drift["summary"]["new_count"] == 1
    assert drift["new"][0]["id"] == "F2"


def test_resolved_finding_detected():
    from agentscan.drift import save_baseline, compute_drift
    save_baseline("t.yaml", [_finding("F1", "HIGH"), _finding("F2", "MEDIUM")])
    drift = compute_drift("t.yaml", [_finding("F1", "HIGH")])
    assert drift["summary"]["resolved_count"] == 1
    assert drift["resolved"][0]["id"] == "F2"


def test_escalated_severity_detected():
    from agentscan.drift import save_baseline, compute_drift
    save_baseline("t.yaml", [_finding("F1", "MEDIUM")])
    drift = compute_drift("t.yaml", [_finding("F1", "CRITICAL")])
    assert drift["summary"]["escalated_count"] == 1
    assert drift["escalated"][0]["from"] == "MEDIUM"
    assert drift["escalated"][0]["to"] == "CRITICAL"


def test_de_escalated_severity_detected():
    from agentscan.drift import save_baseline, compute_drift
    save_baseline("t.yaml", [_finding("F1", "CRITICAL")])
    drift = compute_drift("t.yaml", [_finding("F1", "LOW")])
    assert drift["summary"]["de_escalated_count"] == 1


def test_unchanged_finding_detected():
    from agentscan.drift import save_baseline, compute_drift
    save_baseline("t.yaml", [_finding("F1", "HIGH", tags=["shell_exec"])])
    drift = compute_drift("t.yaml", [_finding("F1", "HIGH", tags=["shell_exec"])])
    assert drift["summary"]["unchanged_count"] == 1
    assert drift["summary"]["new_count"] == 0


def test_fingerprint_resilient_to_title_rewording():
    """
    Regression pattern from mcp-audit: correlating findings by a stable
    fingerprint (id + tags) means re-wording a finding's title/description
    must not cause it to be reported as both 'resolved' and 'new'.
    """
    from agentscan.drift import save_baseline, compute_drift

    old_finding = {"id": "F1", "title": "Original wording here", "severity": "HIGH", "tags": ["shell_exec"]}
    save_baseline("t.yaml", [old_finding])

    reworded_finding = {"id": "F1", "title": "Completely different wording, same underlying issue",
                        "severity": "HIGH", "tags": ["shell_exec"]}
    drift = compute_drift("t.yaml", [reworded_finding])

    assert drift["summary"]["new_count"] == 0
    assert drift["summary"]["resolved_count"] == 0
    assert drift["summary"]["unchanged_count"] == 1
