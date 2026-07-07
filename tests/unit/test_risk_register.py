# -*- coding: utf-8 -*-
"""Tests for the risk acceptance workflow."""
import pytest
import tempfile
import shutil
from pathlib import Path


@pytest.fixture(autouse=True)
def isolated_register(monkeypatch):
    """Each test gets its own risk register file so tests don't pollute each other
    or the real user's ~/.agentscan/risk_register.json."""
    tmp_dir = tempfile.mkdtemp()
    tmp_path = Path(tmp_dir) / "risk_register.json"
    import agentscan.risk_register as rr
    monkeypatch.setattr(rr, "_REGISTER_PATH", tmp_path)
    yield
    shutil.rmtree(tmp_dir, ignore_errors=True)


def test_accept_risk_persists():
    from agentscan.risk_register import accept_risk, is_accepted

    record = accept_risk(
        target="examples/agent.yaml", finding_id="AGT-001",
        finding_title="Test finding", reason="Reviewed by security team",
        accepted_by="Sneh",
    )
    assert record["status"] == "accepted_risk"
    assert record["reviewer"] == "Sneh"

    found = is_accepted("examples/agent.yaml", "AGT-001")
    assert found is not None
    assert found["reason"] == "Reviewed by security team"


def test_is_accepted_returns_none_for_unaccepted_finding():
    from agentscan.risk_register import is_accepted
    assert is_accepted("some/target.yaml", "NEVER-ACCEPTED") is None


def test_revoke_acceptance():
    from agentscan.risk_register import accept_risk, revoke_acceptance, is_accepted

    accept_risk(target="t.yaml", finding_id="F1", finding_title="X",
               reason="ok", accepted_by="A")
    assert is_accepted("t.yaml", "F1") is not None

    revoked = revoke_acceptance("t.yaml", "F1")
    assert revoked is True
    assert is_accepted("t.yaml", "F1") is None

    # Revoking again returns False (nothing to revoke)
    assert revoke_acceptance("t.yaml", "F1") is False


def test_expired_acceptance_treated_as_not_accepted():
    from agentscan.risk_register import accept_risk, is_accepted

    accept_risk(target="t.yaml", finding_id="F2", finding_title="X",
               reason="temporary", accepted_by="A", expires="2020-01-01")
    # Expiry date is in the past -- must be treated as not accepted
    assert is_accepted("t.yaml", "F2") is None


def test_annotate_findings_marks_accepted_status():
    from agentscan.risk_register import accept_risk, annotate_findings

    accept_risk(target="t.yaml", finding_id="F3", finding_title="X",
               reason="ok", accepted_by="A")

    findings = [
        {"id": "F3", "title": "Accepted one"},
        {"id": "F4", "title": "Not accepted"},
    ]
    annotate_findings(findings, "t.yaml")
    assert findings[0]["risk_accepted"] is True
    assert findings[1]["risk_accepted"] is False


def test_risk_acceptance_does_not_remove_finding_from_list():
    """
    Accepted risks must stay visible in the findings list (with a badge),
    never silently disappear -- an auditor must be able to see what was
    accepted and why, not just an absence of the finding.
    """
    from agentscan.risk_register import accept_risk, annotate_findings

    accept_risk(target="t.yaml", finding_id="F5", finding_title="X",
               reason="ok", accepted_by="A")
    findings = [{"id": "F5", "title": "Should stay visible"}]
    result = annotate_findings(findings, "t.yaml")
    assert len(result) == 1
    assert result[0]["risk_accepted"] is True


def test_four_states_supported():
    from agentscan.risk_register import set_finding_status, VALID_STATUSES
    assert VALID_STATUSES == {"open", "accepted_risk", "false_positive", "remediated"}
    for status in ("accepted_risk", "false_positive", "remediated"):
        record = set_finding_status(
            target="t.yaml", finding_id="F-" + status, finding_title="X",
            status=status, reason="test", reviewer="QA",
        )
        assert record["status"] == status


def test_invalid_status_rejected():
    from agentscan.risk_register import set_finding_status
    import pytest as _pytest
    with _pytest.raises(ValueError):
        set_finding_status(target="t.yaml", finding_id="F1", finding_title="X",
                           status="not_a_real_status", reason="x", reviewer="y")


def test_governed_score_excludes_non_open_findings():
    from agentscan.risk_register import set_finding_status, annotate_findings, compute_governed_score

    set_finding_status(target="t.yaml", finding_id="F1", finding_title="Critical issue",
                       status="accepted_risk", reason="compensating control in place", reviewer="QA")

    findings = [
        {"id": "F1", "severity": "CRITICAL", "title": "Critical issue"},
        {"id": "F2", "severity": "HIGH", "title": "Still open issue"},
    ]
    annotate_findings(findings, "t.yaml")
    scores = compute_governed_score(findings, raw_score=65)

    assert scores["raw_score"] == 65
    # Only F2 (HIGH, still open) should count toward governed score
    assert scores["governed_score"] < scores["raw_score"]
    assert scores["findings_excluded_from_governed"] == 1


def test_remediated_and_false_positive_also_excluded_from_governed_score():
    from agentscan.risk_register import set_finding_status, annotate_findings, compute_governed_score

    set_finding_status(target="t2.yaml", finding_id="F1", finding_title="X",
                       status="false_positive", reason="not exploitable", reviewer="QA")
    set_finding_status(target="t2.yaml", finding_id="F2", finding_title="Y",
                       status="remediated", reason="patched in v2", reviewer="QA")

    findings = [
        {"id": "F1", "severity": "CRITICAL", "title": "X"},
        {"id": "F2", "severity": "CRITICAL", "title": "Y"},
        {"id": "F3", "severity": "LOW", "title": "Z"},
    ]
    annotate_findings(findings, "t2.yaml")
    scores = compute_governed_score(findings, raw_score=90)

    assert scores["findings_excluded_from_governed"] == 2
    assert scores["open_findings_count"] == 1
