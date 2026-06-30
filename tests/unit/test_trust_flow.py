"""Tests for Trust Flow Graph analysis."""
import pytest
from agentscan.models import ScanResult
from agentscan.graph.engine import build_graph_from_scan
from agentscan.graph.trust_flow import analyse_trust_flow, TrustLevel, _classify_trust


def make_result(caps, cap_to_tools=None):
    return ScanResult(
        target="test.yaml", scanner_type="agent_scanner",
        metadata={"capabilities_detected": caps, "cap_to_tools": cap_to_tools or {}, "tool_count": len(caps)},
    )


def test_unsanitised_crossing_detected():
    result = make_result(["shell_exec"], {"shell_exec": ["bash_tool"]})
    graph = build_graph_from_scan(result)
    report = analyse_trust_flow(graph)
    assert report.total_unsanitised_crossings > 0


def test_findings_generated_for_crossings():
    result = make_result(["secret_access", "network_egress"])
    graph = build_graph_from_scan(result)
    report = analyse_trust_flow(graph)
    assert report.findings


def test_riskiest_path_identified():
    result = make_result(["shell_exec"], {"shell_exec": ["bash"]})
    graph = build_graph_from_scan(result)
    report = analyse_trust_flow(graph)
    assert report.riskiest_path is not None


def test_safe_capabilities_fewer_crossings():
    safe_result = make_result(["file_read"])
    dangerous_result = make_result(["shell_exec", "secret_access", "network_egress"])
    safe_graph = build_graph_from_scan(safe_result)
    dangerous_graph = build_graph_from_scan(dangerous_result)
    safe_report = analyse_trust_flow(safe_graph)
    dangerous_report = analyse_trust_flow(dangerous_graph)
    assert dangerous_report.total_unsanitised_crossings >= safe_report.total_unsanitised_crossings
