# -*- coding: utf-8 -*-
"""Tests for the attack graph engine."""
import pytest
from agentscan.graph.nodes import Node, Edge, NodeType, EdgeType
from agentscan.graph.engine import AttackGraph, build_graph_from_scan
from agentscan.models import ScanResult, Severity


def make_simple_graph() -> AttackGraph:
    g = AttackGraph()
    tool = Node(id="tool_shell", type=NodeType.TOOL, label="shell_exec")
    g.add_node(tool)
    g.add_edge(Edge(src="user_prompt", dst="tool_shell", type=EdgeType.INJECTS, confidence=0.9))
    g.add_edge(Edge(src="tool_shell", dst="shell_process", type=EdgeType.EXECUTES,
                    confidence=1.0, mitre=["AML.T0017"]))
    return g


def test_reachability():
    g = make_simple_graph()
    reachable = g.reachable_from("user_prompt")
    assert "shell_process" in reachable
    assert "tool_shell" in reachable


def test_shortest_path():
    g = make_simple_graph()
    path = g.shortest_path("user_prompt", "shell_process")
    assert path is not None
    assert path[0] == "user_prompt"
    assert path[-1] == "shell_process"
    assert len(path) == 3


def test_attack_paths_found():
    g = make_simple_graph()
    paths = g.find_attack_paths()
    assert len(paths) >= 1
    crown_ids = [p.crown_jewel.id for p in paths]
    assert "shell_process" in crown_ids


def test_blast_radius():
    g = make_simple_graph()
    br = g.blast_radius("user_prompt")
    assert br["reachable_nodes"] >= 2
    assert "OS Shell / Command Execution" in br["crown_jewels_reachable"]
    assert br["aggregate_impact"] > 0


def test_trust_score_deducts_for_no_auth():
    g = AttackGraph()
    server = Node(id="mcp_srv", type=NodeType.MCP_SERVER, label="Test Server",
                  properties={"has_auth": False})
    g.add_node(server)
    g.add_edge(Edge(src="mcp_srv", dst="shell_process", type=EdgeType.EXECUTES, confidence=1.0))
    ts = g.trust_score("mcp_srv")
    assert ts["trust_score"] < 80
    assert any("auth" in r.lower() for r in ts["deductions"])


def test_build_graph_from_scan():
    result = ScanResult(
        target="test_agent.yaml",
        scanner_type="agent_scanner",
        metadata={
            "capabilities_detected": ["shell_exec", "network_egress", "secret_access"],
            "cap_to_tools": {
                "shell_exec": ["bash_tool"],
                "network_egress": ["http_client"],
                "secret_access": ["vault_reader"],
            },
            "tool_count": 3,
        }
    )
    g = build_graph_from_scan(result)
    paths = g.find_attack_paths()
    assert len(paths) >= 3
    # Exfil path should exist (secret_access + network_egress)
    titles = [p.title for p in paths]
    assert any("Credentials" in t or "AWS" in t for t in titles)


def test_path_scoring_orders_by_impact():
    g = make_simple_graph()
    # Add a lower-impact path
    low = Node(id="log_file", type=NodeType.RESOURCE, label="Log File", crown_jewel_value=10)
    g.add_node(low)
    g.add_edge(Edge(src="tool_shell", dst="log_file", type=EdgeType.READS, confidence=1.0))
    paths = g.find_attack_paths()
    scores = [p.composite_score for p in paths]
    assert scores == sorted(scores, reverse=True)  # highest first


def test_no_false_paths_without_entry():
    """Isolated nodes with no path from attacker entry should not appear."""
    g = AttackGraph()
    isolated = Node(id="isolated_crown", type=NodeType.CROWN_JEWEL, label="Isolated",
                    is_crown_jewel=True, crown_jewel_value=100)
    g.add_node(isolated)
    # No edges connecting to attacker entries
    paths = g.find_attack_paths()
    crown_ids = [p.crown_jewel.id for p in paths]
    assert "isolated_crown" not in crown_ids


def test_open_flag_creates_default_filename():
    """agentscan graph agent --open should write to temp and print the path."""
    import subprocess, os
    from pathlib import Path
    repo_root = Path(__file__).parent.parent.parent
    result = subprocess.run(
        ["agentscan", "graph", "agent", "examples/agent_configs/dangerous_agent.yaml", "--open"],
        capture_output=True, text=True, encoding="utf-8", cwd=str(repo_root),
    )
    assert result.returncode == 0, f"Command failed: {result.stderr[:200]}"
    # --open now writes to a temp file and prints "Interactive graph -> <path>"
    assert "Interactive graph ->" in result.stdout, (
        f"Expected file path in output, got: {result.stdout[:300]}"
    )
