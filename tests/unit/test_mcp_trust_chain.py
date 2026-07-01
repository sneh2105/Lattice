# -*- coding: utf-8 -*-
"""Tests for MCP multi-server trust chain analyser."""
import pytest
from agentscan.scanners.mcp_scanner_v2 import MCPServerProfile, _build_mcp_graph, MCPToolAnalysis
from agentscan.scanners.mcp_trust_chain import MCPTrustChain
from agentscan.graph.engine import AttackGraph
from agentscan.graph.nodes import EdgeType
from agentscan.models import Severity

# Cap → (target_crown_node, EdgeType, mitre)
CAP_EDGES = {
    "shell_exec":     ("shell_process",      EdgeType.EXECUTES,    ["AML.T0017"]),
    "code_execution": ("shell_process",      EdgeType.EXECUTES,    ["AML.T0017"]),
    "secret_access":  ("aws_credentials",    EdgeType.READS,       ["AML.T0051"]),
    "network_egress": ("external_network",   EdgeType.EXFILTRATES, ["AML.T0040"]),
    "database":       ("database_contents",  EdgeType.READS,       ["AML.T0051"]),
    "file_write":     ("filesystem",         EdgeType.WRITES,      ["AML.T0048"]),
    "file_read":      ("filesystem",         EdgeType.READS,       ["AML.T0051"]),
}

def make_profile(name: str, trust_score: int, capabilities: list[str],
                 has_auth: bool = True) -> MCPServerProfile:
    """Create a realistic MCPServerProfile with proper graph edges."""
    server_id = f"mcp_{name}"
    fake_tools = []
    for cap in capabilities:
        tool_node_id = f"tool_{server_id}_{cap[:20]}"
        edges = []
        if cap in CAP_EDGES:
            crown, etype, mitre = CAP_EDGES[cap]
            edges.append((tool_node_id, crown, etype, 1.0, mitre))
        fake_tools.append(MCPToolAnalysis(
            name=cap, description=cap, capabilities=[cap],
            severity=Severity.CRITICAL, trust_deduction=25,
            findings=[], graph_edges=edges,
        ))
    graph = _build_mcp_graph(name, server_id, fake_tools, has_auth)
    return MCPServerProfile(
        name=name, url_or_path=f"test://{name}", is_live=False,
        trust_score=trust_score,
        trust_level="HIGH" if trust_score>=70 else "MEDIUM" if trust_score>=40 else "LOW",
        risk_score=100 if "shell_exec" in capabilities else 50,
        tool_count=len(capabilities),
        tools=fake_tools, findings=[], attack_paths=[],
        trust_deductions=[],
        publisher="test", has_auth=has_auth, has_wildcard_perms=False,
        capabilities=capabilities, graph=graph,
    )


def test_trust_propagation_reduces_upstream():
    chain = MCPTrustChain()
    chain.add_server_profile(make_profile("safe-server", 85, ["file_read"]))
    chain.add_server_profile(make_profile("risky-server", 15, ["shell_exec", "secret_access"], has_auth=False))
    chain.declare_calls("safe-server", "risky-server")
    report = chain.analyse()
    safe_result = report.trust_propagation["safe-server"]
    assert safe_result.effective_trust < safe_result.declared_trust
    assert "risky-server" in safe_result.poisoned_by


def test_trust_floor_is_lowest_effective_in_chain():
    chain = MCPTrustChain()
    chain.add_server_profile(make_profile("server-a", 90, []))
    chain.add_server_profile(make_profile("server-b", 60, ["database"]))
    chain.add_server_profile(make_profile("server-c", 10, ["shell_exec"]))
    chain.declare_calls("server-a", "server-b")
    chain.declare_calls("server-b", "server-c")
    report = chain.analyse()
    assert report.effective_trust_floor < 50


def test_weakest_server_identified():
    chain = MCPTrustChain()
    chain.add_server_profile(make_profile("strong", 80, ["file_read"]))
    chain.add_server_profile(make_profile("weak", 15, ["shell_exec", "network_egress"]))
    chain.declare_calls("strong", "weak")
    report = chain.analyse()
    assert report.weakest_server == "weak"


def test_trust_pollution_finding_generated():
    chain = MCPTrustChain()
    chain.add_server_profile(make_profile("upstream", 85, []))
    chain.add_server_profile(make_profile("downstream", 10, ["shell_exec"]))
    chain.declare_calls("upstream", "downstream")
    report = chain.analyse()
    pollution = [f for f in report.findings if "pollution" in f.id.lower()]
    assert pollution
    assert pollution[0].severity in (Severity.HIGH, Severity.CRITICAL)


def test_no_propagation_without_edges():
    chain = MCPTrustChain()
    chain.add_server_profile(make_profile("server-a", 90, []))
    chain.add_server_profile(make_profile("server-b", 10, ["shell_exec"]))
    report = chain.analyse()
    a_result = report.trust_propagation["server-a"]
    assert a_result.effective_trust == a_result.declared_trust
    assert not a_result.poisoned_by


def test_cycle_detection_does_not_crash():
    chain = MCPTrustChain()
    chain.add_server_profile(make_profile("server-a", 70, ["file_read"]))
    chain.add_server_profile(make_profile("server-b", 60, ["database"]))
    chain.declare_calls("server-a", "server-b")
    chain.declare_calls("server-b", "server-a")
    report = chain.analyse()
    assert report is not None
    assert len(report.trust_propagation) == 2


def test_three_server_chain_with_pollution():
    chain = MCPTrustChain()
    chain.add_server_profile(make_profile("frontend", 80, []))
    chain.add_server_profile(make_profile("orchestrator", 65, ["database"]))
    chain.add_server_profile(make_profile("executor", 20, ["shell_exec", "secret_access", "network_egress"]))
    chain.declare_calls("frontend", "orchestrator")
    chain.declare_calls("orchestrator", "executor")
    report = chain.analyse()
    frontend = report.trust_propagation["frontend"]
    assert frontend.trust_reduction > 0
    assert report.weakest_server == "executor"


def test_unified_graph_has_crown_jewels():
    chain = MCPTrustChain()
    chain.add_server_profile(make_profile("server-a", 80, ["file_read"]))
    chain.add_server_profile(make_profile("server-b", 30, ["shell_exec"]))
    report = chain.analyse()
    node_ids = set(report.unified_graph.nodes.keys())
    assert "user_prompt" in node_ids
    assert "shell_process" in node_ids


def test_cross_server_attack_paths_via_graph():
    """Executor with shell+secret+network should generate attack paths in unified graph."""
    chain = MCPTrustChain()
    chain.add_server_profile(make_profile("frontend", 80, []))
    chain.add_server_profile(make_profile("executor", 20,
                             ["shell_exec", "secret_access", "network_egress"]))
    chain.declare_calls("frontend", "executor")
    report = chain.analyse()
    # The unified graph should find paths from user_prompt to crown jewels
    paths = report.unified_graph.find_attack_paths()
    assert len(paths) >= 1


def test_combined_capability_paths():
    """Two servers each with one capability that's harmless alone but dangerous together."""
    chain = MCPTrustChain()
    chain.add_server_profile(make_profile("secrets-server", 70, ["secret_access"]))
    chain.add_server_profile(make_profile("network-server", 70, ["network_egress"]))
    # No explicit calls — agent uses both simultaneously
    report = chain.analyse()
    # unified graph has aws_credentials and external_network
    # the cross-server chaining edges should create a path
    node_ids = set(report.unified_graph.nodes.keys())
    assert "aws_credentials" in node_ids
    assert "external_network" in node_ids
