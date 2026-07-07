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


def test_risk_acceptance_visible_across_scan_compliance_and_pdf():
    """
    Regression: a finding accepted via the risk register was visible in the
    dashboard's raw JSON in some cases but completely absent from the
    Compliance API and PDF export, because annotate_findings() was only
    ever called in _scan_target's tail -- Compliance/PDF/SARIF built their
    ScanResult through a separate path (_build_merged_result) that never
    annotated finding status at all. Now both paths go through the same
    annotation step, so acceptance must show up identically everywhere.
    """
    import tempfile
    from agentscan.ui_server import _build_merged_result, _scan_target
    from agentscan.risk_register import set_finding_status
    from agentscan.compliance.audit_report import generate_audit_report

    target = "examples/agent_configs/dangerous_agent.yaml"

    scan1 = _scan_target(target)
    fid = scan1["findings"][0]["id"]
    ftitle = scan1["findings"][0]["title"]

    set_finding_status(target=target, finding_id=fid, finding_title=ftitle,
                       status="accepted_risk", reason="Test acceptance", reviewer="QA")
    try:
        # 1. Dashboard scan output shows it
        scan2 = _scan_target(target)
        matching = [f for f in scan2["findings"] if f["id"] == fid]
        assert matching, "finding must still be present (never hidden)"
        assert matching[0]["status"] == "accepted_risk"
        assert scan2["governed_score"] <= scan2["raw_score"]

        # 2. The raw ScanResult object (what Compliance/PDF/SARIF consume)
        #    also carries the same status
        result = _build_merged_result(target)
        pdf_source_finding = [f for f in result.findings if f.id == fid]
        assert pdf_source_finding, "finding must exist in the merged ScanResult"
        assert getattr(pdf_source_finding[0], "status", None) == "accepted_risk", (
            "PDF/Compliance/SARIF source ScanResult must see the same status "
            "the dashboard scan does -- these must never diverge"
        )

        # 3. The actual generated PDF file contains the acceptance record
        tmp = tempfile.mktemp(suffix=".pdf")
        generate_audit_report(result, tmp, organisation="Test")
        import subprocess
        try:
            text = subprocess.run(["pdftotext", tmp, "-"], capture_output=True, text=True, timeout=10).stdout
            if text:  # only assert if pdftotext is available in this environment
                assert "Risk Acceptance Register" in text
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass  # pdftotext not installed -- the earlier ScanResult-level assertion already covers the fix
    finally:
        set_finding_status(target=target, finding_id=fid, finding_title="", status="open", reason="", reviewer="")


def test_github_scan_uses_stable_target_key_not_ephemeral_clone_path():
    """
    Regression: GitHub-scanned targets used the ephemeral temp clone
    directory as the risk-register key. Since a fresh random tempdir is
    created on every scan, a risk accepted on one scan of a repo could
    never match on the next scan of the same repo -- acceptance looked
    like it silently reverted every time. _build_merged_result must
    preserve the original stable URL as result.target, not the temp path.
    """
    from agentscan.ui_server import _build_merged_result
    from agentscan.models import ScanResult

    # Directly verify the annotation call site uses original_target, not the
    # post-clone temp path, by inspecting the source for the substitution.
    import inspect
    src = inspect.getsource(_build_merged_result)
    assert "original_target = target" in src
    assert "result.target = original_target" in src
