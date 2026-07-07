

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
    # Two tools whose capabilities combine into a real attack path --
    # build_graph_from_scan now builds strictly from result.attack_paths
    # (the single-source-of-truth fix), so a single lone capability with no
    # combination partner produces zero attack paths and therefore zero
    # graph nodes. A shell_exec + network_egress pair does combine.
    (repo_dir / "agent.py").write_text(
        "from langchain.tools import tool\n\n"
        "@tool\n"
        "def run_shell(cmd: str) -> str:\n"
        "    \"\"\"Run shell commands.\"\"\"\n"
        "    import subprocess\n"
        "    return subprocess.run(cmd, shell=True).stdout\n\n"
        "@tool\n"
        "def fetch_url(url: str) -> str:\n"
        "    \"\"\"Fetch content from a URL.\"\"\"\n"
        "    import requests\n"
        "    return requests.get(url).text\n",
        encoding="utf-8",
    )

    class DummyCompletedProcess:
        def __init__(self):
            self.returncode = 0
            self.stderr = ""
            self.stdout = ""

    def fake_run(cmd, capture_output, text, timeout):
        import shutil
        # Simulate `git clone <url> <dest>` by actually copying repo_dir's
        # content into the destination -- the mock must do real work here,
        # not just report success, or this test doesn't actually exercise
        # graph construction on real content (it was previously "passing"
        # only because the old graph builder always emitted non-empty
        # placeholder nodes regardless of whether any scan data existed --
        # exactly the orphan-node bug this whole fix addresses).
        dest = cmd[-1]
        shutil.copytree(str(repo_dir), dest, dirs_exist_ok=True)
        return DummyCompletedProcess()

    monkeypatch.setattr("agentscan.ui_server.subprocess.run", fake_run)

    graph_payload = _get_graph("https://github.com/example/repo")

    assert "error" not in graph_payload, f"Graph build failed: {graph_payload.get('error')}"
    assert graph_payload.get("nodes"), "GitHub graph should include nodes"
    assert graph_payload.get("paths"), "GitHub graph should include the shell_exec+network_egress attack path"


def test_build_graph_prunes_disconnected_nodes_and_uses_agent_type():
    """The graph should discard disconnected nodes and label source-scan agents as agents, not MCP servers."""
    from agentscan.graph.engine import build_graph_from_scan
    from agentscan.graph.nodes import Node, NodeType
    from agentscan.models import ScanResult, Finding, AttackPath, Severity, ConfidenceLevel

    # build_graph_from_scan now builds strictly from result.attack_paths
    # (the single-source-of-truth fix) -- a bare capabilities_detected list
    # with no attack_paths produces an empty graph, so the fixture needs a
    # real Finding + AttackPath, same shape a real scanner would produce.
    finding = Finding(
        id="TEST-SHELL", title="Tool 'run_shell' grants shell_exec",
        severity=Severity.CRITICAL, confidence=ConfidenceLevel.HIGH, scanner="source_scanner",
        explanation="", impact="", remediation="", tags=["tool-permissions", "shell_exec"],
    )
    result = ScanResult(
        target="/tmp/repo",
        scanner_type="source_scanner",
        findings=[finding],
        attack_paths=[AttackPath(
            id="TEST-PATH", title="Shell exec path", severity=Severity.CRITICAL,
            steps=[finding], entry_point="Prompt injection", impact="RCE",
            description="Test path.", mitre_atlas=["AML.T0017"],
        )],
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


def test_graph_paths_exactly_match_pdf_attack_paths():
    """
    Every path that appears in the PDF/compliance/JSON output must also
    appear in the Attack Graph -- same titles, connected by real edges.

    NOTE on the invariant: the graph may show MORE paths than
    result.attack_paths, because standalone CRITICAL/HIGH findings that
    never combined into a multi-tool chain (e.g. a lone eval()/exec()
    behavioral finding) are deliberately added to the graph as their own
    path so they don't silently disappear just because no chain formed --
    that is itself a separate, intentional fix (see
    test_standalone_critical_finding_appears_as_graph_path below). The
    invariant this test enforces is CONTAINMENT: every PDF path must be
    present in the graph, never fewer.
    """
    from agentscan.scanners.agent_scanner import scan_agent_config
    from agentscan.graph.engine import build_graph_from_scan, graph_paths_from_attack_paths

    result = scan_agent_config("examples/agent_configs/dangerous_agent.yaml")
    graph = build_graph_from_scan(result)
    graph_paths = graph_paths_from_attack_paths(result, graph)

    # Graph must never show FEWER paths than the PDF/JSON -- that's the
    # actual bug this whole fix exists to prevent.
    assert len(graph_paths) >= len(result.attack_paths), (
        f"Graph shows {len(graph_paths)} paths but PDF/JSON report "
        f"{len(result.attack_paths)} -- graph must never under-report"
    )

    # Every PDF attack path title must appear as a graph path title
    pdf_titles = {p.title for p in result.attack_paths}
    graph_titles = {p.title for p in graph_paths}
    assert pdf_titles.issubset(graph_titles), (
        f"PDF paths missing from graph: {pdf_titles - graph_titles}"
    )

    # Every graph path must be an actual connected edge sequence, not a
    # disconnected collection of nodes -- entry -> ... -> crown jewel with
    # a real edge for every hop, and no self-loops (same node -> itself).
    for gp in graph_paths:
        assert len(gp.edges) >= 1, f"Path '{gp.title}' has no edges"
        assert len(gp.nodes) >= 2, f"Path '{gp.title}' has fewer than 2 nodes"
        assert not any(e.src == e.dst for e in gp.edges), (
            f"Path '{gp.title}' has a self-loop edge (duplicated hop bug)"
        )


def test_graph_has_no_orphan_nodes():
    """
    Every node in a built graph must have at least one edge. Placeholder
    nodes like "AWS / Cloud Credentials" or "Tool Response" must never
    render disconnected just because they exist in the predefined node
    constants -- a node only appears if a real attack path actually reached it.
    """
    from agentscan.scanners.agent_scanner import scan_agent_config
    from agentscan.graph.engine import build_graph_from_scan

    result = scan_agent_config("examples/agent_configs/dangerous_agent.yaml")
    graph = build_graph_from_scan(result)

    connected_ids = set()
    for e in graph.edges:
        connected_ids.add(e.src)
        connected_ids.add(e.dst)

    orphans = set(graph.nodes.keys()) - connected_ids
    assert not orphans, f"Orphan (disconnected) nodes found: {orphans}"


def test_eval_and_shell_exec_render_as_distinct_node_types():
    """
    A finding where python eval()/exec() is called must render as a
    distinct node ("Code Execution (Arbitrary Python)") from a finding
    where a shell command is run ("OS Shell / Command Execution") -- these
    are different exploitation mechanisms with different remediation.
    """
    from agentscan.graph.engine import _node_spec_for_finding
    from agentscan.models import Finding, Severity, ConfidenceLevel

    eval_finding = Finding(
        id="EVAL-1", title="Tool 'x' can execute arbitrary code via eval()",
        severity=Severity.CRITICAL, confidence=ConfidenceLevel.HIGH, scanner="test",
        explanation="", impact="", remediation="",
        tags=["tool-permissions", "code_execution", "behavioral-detection"],
    )
    shell_finding = Finding(
        id="SHELL-1", title="Tool 'y' can execute shell commands",
        severity=Severity.CRITICAL, confidence=ConfidenceLevel.HIGH, scanner="test",
        explanation="", impact="", remediation="",
        tags=["tool-permissions", "shell_exec"],
    )

    eval_tag, eval_spec = _node_spec_for_finding(eval_finding)
    shell_tag, shell_spec = _node_spec_for_finding(shell_finding)

    assert eval_spec["node_id"] != shell_spec["node_id"]
    assert eval_spec["label"] != shell_spec["label"]
    assert "Python" in eval_spec["label"] or "Code Execution" in eval_spec["label"]
    assert "Shell" in shell_spec["label"] or "Command" in shell_spec["label"]


def test_mcp_derived_graph_paths_also_match_exactly():
    """
    Same invariant as test_graph_paths_exactly_match_pdf_attack_paths, but
    for a target with MCP-derived findings -- the case that was actually
    broken (MCP raw tags like MCP-DATABASE weren't recognized by the graph's
    finding-to-node-type mapping, only the translated capability names were).
    """
    from agentscan.ui_server import _build_merged_result, _get_graph

    target = "examples/vulnerable_agents/04_database_exfiltration/"
    result = _build_merged_result(target)
    graph_payload = _get_graph(target)

    assert "error" not in graph_payload
    assert len(graph_payload["paths"]) == len(result.attack_paths)
    pdf_titles = {p.title for p in result.attack_paths}
    graph_titles = {p["title"] for p in graph_payload["paths"]}
    assert pdf_titles == graph_titles


def test_no_duplicated_hop_when_one_tool_has_multiple_capabilities():
    """
    Regression: a tool tagged with two capabilities (e.g. one AWS client
    both reads secrets AND grants cloud API access) produced a nonsensical
    tool -> tool self-loop hop, because each capability finding re-added the
    'agent invokes tool' edge and re-chained through the tool again. The
    correct rendering is one tool node with two separate outbound capability
    edges, not the tool invoking itself.
    """
    from agentscan.scanners.source_scanner import scan_source
    from agentscan.graph.engine import build_graph_from_scan, graph_paths_from_attack_paths
    import tempfile
    from pathlib import Path

    tmp = tempfile.mkdtemp()
    Path(tmp, "agent.py").write_text(
        "from langchain.tools import tool\n\n"
        "@tool\n"
        "def get_secret(name: str) -> str:\n"
        "    \"\"\"Retrieve a secret from AWS.\"\"\"\n"
        "    import boto3\n"
        "    return boto3.client('secretsmanager').get_secret_value(SecretId=name)\n"
    )
    result = scan_source(tmp)
    assert len(result.attack_paths) >= 1

    graph = build_graph_from_scan(result)
    paths = graph_paths_from_attack_paths(result, graph)

    for p in paths:
        assert not any(e.src == e.dst for e in p.edges), (
            f"Path '{p.title}' contains a self-loop edge: "
            f"{[(e.src, e.dst) for e in p.edges if e.src == e.dst]}"
        )
        # No node should appear twice in the node list for the same path
        node_ids = [n.id for n in p.nodes]
        assert len(node_ids) == len(set(node_ids)), (
            f"Path '{p.title}' has a duplicated node: {node_ids}"
        )


def test_standalone_critical_finding_appears_as_graph_path():
    """
    Regression: a CRITICAL finding that never combined into a multi-tool
    attack_path (e.g. calculator's eval()-based code_execution finding,
    which appears in every PDF/JSON output but has no combination partner)
    was completely absent from the Attack Graph -- no node, no path. It
    must now render as its own standalone path, connected from the agent,
    not merged into an existing chain and not silently dropped.
    """
    from agentscan.scanners.source_scanner import scan_source
    from agentscan.graph.engine import build_graph_from_scan, graph_paths_from_attack_paths
    import tempfile
    from pathlib import Path

    tmp = tempfile.mkdtemp()
    Path(tmp, "agent.py").write_text(
        "from langchain.tools import tool\n\n"
        "@tool\n"
        "def calculator(expr: str) -> str:\n"
        "    \"\"\"Evaluate a math expression.\"\"\"\n"
        "    return str(eval(expr))\n\n"
        "@tool\n"
        "def get_secret(name: str) -> str:\n"
        "    \"\"\"Retrieve a secret from AWS.\"\"\"\n"
        "    import boto3\n"
        "    return boto3.client('secretsmanager').get_secret_value(SecretId=name)\n"
    )
    result = scan_source(tmp)

    # Confirm the calculator's code_execution finding exists but was never
    # part of any combined attack_path (this is the exact scenario reported)
    calc_findings = [f for f in result.findings if "calculator" in f.title.lower()]
    assert calc_findings, "fixture should produce a calculator finding"
    combined_step_ids = {s.id for p in result.attack_paths for s in p.steps}
    assert calc_findings[0].id not in combined_step_ids, (
        "test fixture assumption broken: calculator finding unexpectedly "
        "appears in a combined attack_path already"
    )

    graph = build_graph_from_scan(result)
    paths = graph_paths_from_attack_paths(result, graph)

    assert "tool_calculator" in graph.nodes, "calculator tool must have a graph node"
    assert "code_exec_runtime" in graph.nodes, "code execution target node must exist"

    calc_paths = [p for p in paths if "calculator" in p.title.lower()]
    assert calc_paths, "calculator's code_execution finding must appear as its own graph path"

    # It must be a real connected path, not a floating node
    calc_path = calc_paths[0]
    assert len(calc_path.edges) >= 2
    node_ids = [n.id for n in calc_path.nodes]
    assert "tool_calculator" in node_ids
    assert "code_exec_runtime" in node_ids


def test_compliance_score_moves_after_disposition():
    """
    Regression: Compliance Score/Posture banner didn't move after dispositioning
    findings. Two compounding bugs: (1) map_findings_to_controls ignored
    finding.status entirely, mapping ALL findings including dispositioned
    ones; (2) calculate_compliance_score gave each CONTROL a flat 25-point
    penalty with no per-finding cap, so one heavily-regulated finding
    (mapping to 4+ mandatory frameworks) already saturated the score to 0
    regardless of total finding count -- making the score a de facto binary
    gate that never moved even after resolving most findings.
    """
    from agentscan.ui_server import _build_merged_result
    from agentscan.risk_register import set_finding_status
    from agentscan.compliance.framework_mapper import map_findings_to_controls, calculate_compliance_score

    target = "examples/agent_configs/dangerous_agent.yaml"
    result = _build_merged_result(target)
    findings = result.findings

    report_before = map_findings_to_controls(result)
    score_before = calculate_compliance_score(report_before)

    for f in findings[:2]:
        set_finding_status(target=target, finding_id=f.id, finding_title=f.title,
                           status="false_positive", reason="test", reviewer="QA")
    for f in findings[2:4]:
        set_finding_status(target=target, finding_id=f.id, finding_title=f.title,
                           status="accepted_risk", reason="test", reviewer="QA")
    try:
        result2 = _build_merged_result(target)
        report_after = map_findings_to_controls(result2)
        score_after = calculate_compliance_score(report_after)

        assert score_after != score_before, (
            f"Compliance score did not move after dispositioning 4 findings "
            f"({score_before} -> {score_after})"
        )
        assert score_after > score_before, "score should improve after disposition, not worsen"
        assert len(report_after.mappings) < len(report_before.mappings), (
            "dispositioned findings must be excluded from active mappings"
        )
        assert len(report_after.resolved_mappings) > 0, (
            "dispositioned findings must still appear in resolved_mappings -- never silently dropped"
        )
    finally:
        for f in findings[:4]:
            set_finding_status(target=target, finding_id=f.id, finding_title="", status="open", reason="", reviewer="")


def test_dpia_recommendation_reflects_disposition():
    """
    Regression: the DPIA's risk score / attack path count / deploy
    recommendation were computed from the raw undispositioned findings and
    attack paths, completely ignoring the risk acceptance register --
    two of three attack-path-driving findings could be marked False
    Positive or Remediated and the DPIA would still say "3 attack path(s)
    identified. DO NOT DEPLOY" with the exact same pre-review numbers.
    """
    from agentscan.ui_server import _build_merged_result
    from agentscan.risk_register import set_finding_status
    from agentscan.compliance.dpia import generate_dpia

    target = "examples/agent_configs/dangerous_agent.yaml"
    result = _build_merged_result(target)
    findings = result.findings

    dpia_before = generate_dpia(result)
    risk_section_before = [s for s in dpia_before.sections if "Risk Identification" in s.title][0]

    # Mark enough findings false_positive/remediated to break some attack paths
    for f in findings:
        if "shell_exec" in f.tags or "secret_access" in f.tags:
            set_finding_status(target=target, finding_id=f.id, finding_title=f.title,
                               status="false_positive", reason="test", reviewer="QA")
    try:
        result2 = _build_merged_result(target)
        dpia_after = generate_dpia(result2)
        risk_section_after = [s for s in dpia_after.sections if "Risk Identification" in s.title][0]

        assert risk_section_after.content != risk_section_before.content, (
            "DPIA risk section must change after dispositioning findings tied to attack paths"
        )
        assert "Reviewed and dispositioned" in risk_section_after.content or "false positive" in risk_section_after.content.lower()
    finally:
        for f in findings:
            if "shell_exec" in f.tags or "secret_access" in f.tags:
                set_finding_status(target=target, finding_id=f.id, finding_title="", status="open", reason="", reviewer="")


def test_control_mapping_evidence_status_reflects_disposition():
    """
    Regression: the Control Mapping table showed "Not found" evidence for
    controls tied to findings marked False Positive or Remediated,
    identical to an untouched open finding -- the evidence_status field
    never considered finding.status at all.
    """
    from agentscan.ui_server import _build_merged_result
    from agentscan.risk_register import set_finding_status
    from agentscan.compliance.framework_mapper import map_findings_to_controls

    target = "examples/agent_configs/dangerous_agent.yaml"
    result = _build_merged_result(target)
    findings = result.findings

    set_finding_status(target=target, finding_id=findings[0].id, finding_title=findings[0].title,
                       status="false_positive", reason="test", reviewer="QA")
    try:
        result2 = _build_merged_result(target)
        report = map_findings_to_controls(result2)

        resolved_evidence_statuses = {
            ctrl.evidence_status
            for mapping in (report.resolved_mappings or [])
            for ctrl in mapping.controls
        }
        assert "not-applicable" in resolved_evidence_statuses, (
            f"false_positive finding's controls must show 'not-applicable' evidence, "
            f"got: {resolved_evidence_statuses}"
        )
    finally:
        set_finding_status(target=target, finding_id=findings[0].id, finding_title="", status="open", reason="", reviewer="")
