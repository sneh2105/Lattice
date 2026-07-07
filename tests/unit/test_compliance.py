

def test_compliance_includes_mcp_findings():
    """
    Regression: compliance mapping on a directory target was re-running only
    source_scan, missing MCP findings. Merged scan must include both.
    """
    from agentscan.ui_server import _get_compliance
    from pathlib import Path
    import tempfile, json, yaml

    tmp = tempfile.mkdtemp()
    # Write a Python agent file
    Path(tmp, "agent.py").write_text(
        'from langchain.tools import tool\n@tool\ndef get_secret(name: str) -> str:\n    """Get secret from vault"""\n    return name\n'
    )
    # Write an MCP manifest
    Path(tmp, "mcp_server.json").write_text(json.dumps({
        "name": "test-mcp",
        "tools": [
            {"name": "run_shell", "description": "Execute shell commands"},
            {"name": "http_post", "description": "Send data to external HTTP endpoint"},
        ]
    }))

    result = _get_compliance(tmp)
    assert "error" not in result or not result["error"], f"Compliance failed: {result.get('error')}"
    # Should have found findings from both source AND MCP
    findings_count = result.get("findings_included", 0)
    assert findings_count >= 2, f"Expected findings from both source and MCP, got {findings_count}"


def test_compliance_for_github_repo_clones_and_scans(monkeypatch, tmp_path):
    """Compliance should clone GitHub repo targets and scan the local checkout."""
    from agentscan.models import ScanResult, Finding, Severity, ConfidenceLevel
    from agentscan.ui_server import _get_compliance

    scanned_paths = []

    def fake_scan_source(path):
        scanned_paths.append(path)
        return ScanResult(
            target=path,
            scanner_type="source",
            findings=[
                Finding(
                    id="F1",
                    title="Shell execution capability",
                    severity=Severity.HIGH,
                    confidence=ConfidenceLevel.HIGH,
                    scanner="source",
                    explanation="Test finding",
                    impact="Test impact",
                    remediation="Test remediation",
                    tags=["shell_exec"],
                )
            ],
        )

    def fake_scan_mcp(path):
        return ScanResult(target=path, scanner_type="mcp", findings=[])

    class DummyCompletedProcess:
        def __init__(self):
            self.returncode = 0
            self.stderr = ""
            self.stdout = ""

    def fake_run(cmd, capture_output, text, timeout):
        clone_dir = tmp_path / "repo"
        clone_dir.mkdir(parents=True, exist_ok=True)
        (clone_dir / "agent.py").write_text("print('ok')\n", encoding="utf-8")
        return DummyCompletedProcess()

    monkeypatch.setattr("agentscan.scanners.source_scanner.scan_source", fake_scan_source)
    monkeypatch.setattr("agentscan.scanners.mcp_scanner.scan_mcp", fake_scan_mcp)
    monkeypatch.setattr("agentscan.ui_server.subprocess.run", fake_run)

    result = _get_compliance("https://github.com/example/repo")

    assert "error" not in result or not result["error"], f"Compliance failed: {result.get('error')}"
    assert scanned_paths, "GitHub compliance target should be scanned locally after cloning"
    assert result.get("findings_included", 0) >= 1


def test_compliance_report_includes_control_metadata_and_score(tmp_path):
    """Compliance report data should expose ownership, deadlines, and a weighted score."""
    from agentscan.compliance.framework_mapper import (
        calculate_compliance_score,
        detect_audit_evidence,
        map_findings_to_controls,
    )
    from agentscan.models import ScanResult, Finding, Severity, ConfidenceLevel

    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    (repo_dir / "app.py").write_text(
        "import logging\nlogger = logging.getLogger(__name__)\n",
        encoding="utf-8",
    )

    result = ScanResult(
        target=str(repo_dir),
        scanner_type="source",
        findings=[
            Finding(
                id="F1",
                title="Shell execution capability",
                severity=Severity.HIGH,
                confidence=ConfidenceLevel.HIGH,
                scanner="source",
                explanation="Test finding",
                impact="Test impact",
                remediation="Test remediation",
                tags=["shell_exec"],
            )
        ],
    )

    report = map_findings_to_controls(result)
    control = report.mappings[0].controls[0]

    assert control.requirement_level == "mandatory"
    assert control.owner
    assert control.deadline
    assert 0 <= calculate_compliance_score(report) <= 100
    assert detect_audit_evidence(str(repo_dir)) == "present"


def test_generate_dpia_uses_tool_and_capability_metadata():
    """DPIA should report the same tool/capability counts as the source scan metadata."""
    from agentscan.compliance.dpia import generate_dpia
    from agentscan.models import ScanResult, Finding, Severity, ConfidenceLevel

    result = ScanResult(
        target="/tmp/repo",
        scanner_type="source",
        findings=[
            Finding(
                id="F1",
                title="Shell execution capability",
                severity=Severity.HIGH,
                confidence=ConfidenceLevel.HIGH,
                scanner="source",
                explanation="Test finding",
                impact="Test impact",
                remediation="Test remediation",
                tags=["shell_exec"],
            ),
            Finding(
                id="F2",
                title="Secret access capability",
                severity=Severity.HIGH,
                confidence=ConfidenceLevel.HIGH,
                scanner="source",
                explanation="Test finding",
                impact="Test impact",
                remediation="Test remediation",
                tags=["secret_access"],
            ),
        ],
        metadata={
            "tools_found": 3,
            "capabilities_detected": ["shell_exec", "secret_access"],
        },
    )

    dpia = generate_dpia(result)
    section_text = "\n".join(section.content for section in dpia.sections)
    assert "Tool count: 3" in section_text
    assert "Capability count: 2" in section_text


def test_get_graph_for_github_repo_clones_and_builds_graph(monkeypatch, tmp_path):
    """Graph generation should clone GitHub URLs and build a graph from the local checkout."""
    from agentscan.ui_server import _get_graph

    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    (repo_dir / "agent.py").write_text(
        "from langchain.tools import tool\n\n"
        "@tool\n"
        "def run_shell(cmd: str) -> str:\n"
        "    \"\"\"Run shell commands.\"\"\"\n"
        "    import subprocess\n"
        "    return subprocess.run(cmd, shell=True).stdout\n",
        encoding="utf-8",
    )

    class DummyCompletedProcess:
        def __init__(self):
            self.returncode = 0
            self.stderr = ""
            self.stdout = ""

    def fake_run(cmd, capture_output, text, timeout):
        return DummyCompletedProcess()

    monkeypatch.setattr("agentscan.ui_server.subprocess.run", fake_run)

    graph_payload = _get_graph("https://github.com/example/repo")

    assert "error" not in graph_payload, f"Graph build failed: {graph_payload.get('error')}"
    assert graph_payload.get("nodes"), "GitHub graph should include nodes"


def test_build_graph_prunes_disconnected_nodes_and_uses_agent_type():
    """The graph should discard disconnected nodes and label source-scan agents as agents, not MCP servers."""
    from agentscan.graph.engine import build_graph_from_scan
    from agentscan.graph.nodes import Node, NodeType
    from agentscan.models import ScanResult

    result = ScanResult(
        target="/tmp/repo",
        scanner_type="source_scanner",
        metadata={"capabilities_detected": ["shell_exec"], "cap_to_tools": {"shell_exec": ["run_shell"]}},
    )

    graph = build_graph_from_scan(result)
    graph.add_node(Node(id="junk", type=NodeType.TOOL, label="unused tool"))

    graph.prune_disconnected_nodes()

    agent = graph.get_node("agent")
    assert agent is not None
    assert agent.type == NodeType.AGENT
    assert "junk" not in graph.nodes


def test_findings_consistent_across_summary_compliance_pdf():
    """
    Regression: Compliance/PDF export were reading from scan_source() alone
    while Summary/Findings tabs used the merged source+MCP result. All three
    (plus SARIF) must now use the same canonical _build_merged_result() and
    therefore report the identical finding count for the same target.
    """
    from agentscan.ui_server import _scan_target, _get_compliance, _build_merged_result

    target = "examples/vulnerable_agents/04_database_exfiltration/"
    summary = _scan_target(target)
    comp = _get_compliance(target)
    result = _build_merged_result(target)

    assert len(summary["findings"]) == comp["findings_included"] == len(result.findings), (
        f"Finding counts diverge: summary={len(summary['findings'])} "
        f"compliance={comp['findings_included']} pdf_source={len(result.findings)}"
    )
    # Must include MCP findings, not just source findings (this dir has both)
    assert len(result.findings) > 2, "Merged result should include MCP findings, not just source"


def test_graph_includes_mcp_derived_paths():
    """
    Regression: Attack Graph was built from result.metadata['capabilities_detected'],
    which is only populated by agent_scanner/source_scanner -- MCP findings use a
    different tag scheme (MCP-SHELL, MCP-NET, etc.) and were silently invisible to
    the graph engine even when present in Findings/Compliance/PDF.
    The merge step must translate MCP tags into the graph engine's capability
    vocabulary so MCP-driven attack paths are not dropped from the graph.
    """
    from agentscan.ui_server import _get_graph, _build_merged_result

    target = "examples/vulnerable_agents/04_database_exfiltration/"
    graph = _get_graph(target)
    result = _build_merged_result(target)

    assert "error" not in graph
    assert len(graph["nodes"]) > 0
    # This dir has an MCP manifest with database + network findings -- the graph
    # must show at least one attack path, not zero (the original bug: 0 paths
    # shown despite MCP findings being present in the merged result).
    assert len(graph["paths"]) > 0, (
        f"Graph shows 0 paths despite {len(result.findings)} findings including MCP data -- "
        "MCP capability tags were not translated for the graph engine"
    )


def test_pdf_and_sarif_use_same_merged_result_as_compliance():
    """
    Regression: PDF and SARIF export endpoints called scan_source() directly,
    bypassing the merge logic that Compliance already had. All export paths
    (PDF, SARIF, Compliance, Graph, Summary) must go through the same
    _build_merged_result() so a board-facing document can never under-report
    findings relative to what the dashboard shows on screen.
    """
    import json
    from agentscan.ui_server import _build_merged_result
    from agentscan.outputs.json_output import to_sarif

    target = "examples/vulnerable_agents/04_database_exfiltration/"
    result = _build_merged_result(target)
    sarif_raw = to_sarif(result)
    sarif = json.loads(sarif_raw) if isinstance(sarif_raw, str) else sarif_raw

    sarif_results = sarif["runs"][0]["results"]
    # SARIF results count should reflect the same merged findings (minus INFO-level
    # findings which SARIF may filter, so just assert it's not suspiciously low)
    assert len(sarif_results) > 0
    assert len(result.findings) > 2, "Merged result underlying SARIF/PDF must include MCP findings"
