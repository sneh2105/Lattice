"""Tests for Capability Escalation Analysis."""
import pytest
from agentscan.graph.escalation import analyse_capability_escalation


def test_shell_escalates_to_everything():
    report = analyse_capability_escalation(["shell_exec"])
    assert report.effective_risk > report.declared_risk or report.effective_risk == 100
    assert "secret_access" in report.effective_capabilities


def test_file_read_escalates_to_secret_access():
    report = analyse_capability_escalation(["file_read"])
    assert "secret_access" in report.effective_capabilities
    escalation_ids = [p.rule_id for p in report.escalation_paths]
    assert "ESC-FILE-TO-CRED" in escalation_ids


def test_code_execution_escalates_to_shell():
    report = analyse_capability_escalation(["code_execution"])
    assert "shell_exec" in report.effective_capabilities


def test_no_escalation_for_isolated_safe_capability():
    report = analyse_capability_escalation(["memory_read"])
    # memory_read alone shouldn't trigger major escalations
    assert report.escalation_factor <= 2.0


def test_escalation_factor_above_one_for_dangerous_combo():
    report = analyse_capability_escalation(["secret_access", "network_egress"])
    assert report.escalation_factor >= 1.0
    assert "cloud_api" in report.effective_capabilities


def test_findings_include_hidden_capability_explanation():
    report = analyse_capability_escalation(["shell_exec"])
    assert report.findings
    assert any("risk" in f.impact.lower() for f in report.findings)


def test_empty_capabilities_no_escalation():
    report = analyse_capability_escalation([])
    assert report.escalation_factor <= 1.0 or report.declared_risk == 0
    assert report.effective_capabilities == set()
