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
    """
    build_graph_from_scan now builds strictly from result.attack_paths (the
    single-source-of-truth fix for the graph/PDF consistency bug) -- a bare
    capabilities_detected metadata dict with no attack_paths produces an
    empty graph. Use the real agent_scanner on a fixture with combining
    capabilities so real AttackPath objects with real Finding steps exist,
    matching how the graph is actually populated in production.
    """
    from agentscan.scanners.agent_scanner import scan_agent_config
    result = scan_agent_config("examples/agent_configs/dangerous_agent.yaml")
    assert len(result.attack_paths) >= 3, "fixture should combine into several attack paths"

    g = build_graph_from_scan(result)
    from agentscan.graph.engine import graph_paths_from_attack_paths
    paths = graph_paths_from_attack_paths(result, g)

    # Containment, not strict equality: the graph may show additional
    # standalone paths for CRITICAL/HIGH findings that never combined into
    # a multi-tool chain (e.g. a lone eval() finding) -- it must never show
    # FEWER than what PDF/JSON report, which is the actual bug this exists
    # to prevent.
    assert len(paths) >= len(result.attack_paths), (
        "graph must never show fewer paths than result.attack_paths -- "
        "this is the single-source-of-truth invariant the whole fix exists to guarantee"
    )
    pdf_titles = {p.title for p in result.attack_paths}
    graph_titles = {p.title for p in paths}
    assert pdf_titles.issubset(graph_titles), f"PDF paths missing from graph: {pdf_titles - graph_titles}"
    titles = [p.title for p in paths]
    assert any("Credential" in t or "Cloud" in t for t in titles)


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


def test_graph_serialization_no_object_object():
    """
    Regression: graph path steps were serialized as raw Node objects,
    rendering as '[object Object]' in the browser.
    All node IDs in paths must be plain strings.
    """
    from agentscan.scanners.agent_scanner import scan_agent_config
    from agentscan.graph.engine import build_graph_from_scan
    from agentscan.ui_server import _serialize_graph
    import json

    result = scan_agent_config("examples/agent_configs/dangerous_agent.yaml")
    graph = build_graph_from_scan(result)
    paths = graph.find_attack_paths()
    data = _serialize_graph(graph, paths)

    # Must be JSON serializable (no Python objects)
    serialized = json.dumps(data)
    assert "[object Object]" not in serialized

    # All node IDs must be strings
    for node in data["nodes"]:
        assert isinstance(node["id"], str), f"Node id not a string: {type(node['id'])}"
        assert isinstance(node["type"], str), f"Node type not a string: {type(node['type'])}"

    # All edge source/target must be strings
    for edge in data["edges"]:
        assert isinstance(edge["source"], str), f"Edge source not a string: {type(edge['source'])}"
        assert isinstance(edge["target"], str), f"Edge target not a string: {type(edge['target'])}"
        assert isinstance(edge["type"], str), f"Edge type not a string: {type(edge['type'])}"

    # All path node lists must contain strings only
    for path in data["paths"]:
        for nid in path["nodes"]:
            assert isinstance(nid, str), f"Path node id not a string: {type(nid)} = {nid}"


def test_graph_all_paths_have_nodes():
    """All attack paths in the graph must have at least one node ID."""
    from agentscan.scanners.agent_scanner import scan_agent_config
    from agentscan.graph.engine import build_graph_from_scan
    from agentscan.ui_server import _serialize_graph

    result = scan_agent_config("examples/agent_configs/dangerous_agent.yaml")
    graph = build_graph_from_scan(result)
    paths = graph.find_attack_paths()
    data = _serialize_graph(graph, paths)

    assert len(data["paths"]) > 0, "Dangerous agent should have attack paths"
    for path in data["paths"]:
        assert len(path["nodes"]) > 0, f"Path '{path['title']}' has no nodes"


def test_attack_path_steps_are_same_finding_objects_as_scan_result():
    """
    AttackPath.steps must hold the SAME Finding objects (by identity) as
    ScanResult.findings, not copies. This is what makes annotate_finding_objects()
    mutating .status in place automatically consistent across Findings tab,
    Attack Graph, and Compliance/PDF -- there is no second data structure
    that could fall out of sync. See INTERMEDIATE_REPRESENTATION.md.
    """
    from agentscan.scanners.agent_scanner import scan_agent_config

    result = scan_agent_config("examples/agent_configs/dangerous_agent.yaml")
    assert result.attack_paths, "fixture must produce at least one attack path"

    findings_by_id = {f.id: f for f in result.findings}
    checked_any = False
    for path in result.attack_paths:
        for step in path.steps:
            assert step.id in findings_by_id
            assert step is findings_by_id[step.id], (
                f"AttackPath step '{step.id}' is a different object than the "
                f"corresponding entry in result.findings -- mutating one would "
                f"not be visible through the other"
            )
            checked_any = True
    assert checked_any, "no attack path steps were checked -- fixture may be broken"
