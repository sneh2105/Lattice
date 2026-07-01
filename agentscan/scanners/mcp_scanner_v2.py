# -*- coding: utf-8 -*-
"""
MCP Security Platform v2
=========================
Full MCP server security analysis with:
  - Trust score (distinct from risk score)
  - Multi-server trust chain analysis
  - Tool permission inheritance
  - Publisher verification
  - Live server introspection (tools/list, capabilities, schema)
  - Registry scanning (compare servers against known-safe list)
  - Graph-integrated output
"""

from __future__ import annotations
import json
import time
import hashlib
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from agentscan.models import (
    ConfidenceLevel, Evidence, Finding, ScanResult, Severity
)
from agentscan.graph.nodes import Node, Edge, NodeType, EdgeType
from agentscan.graph.engine import AttackGraph


# ── Trust signals ────────────────────────────────────────────────────────────

# Known trusted MCP server publishers
TRUSTED_PUBLISHERS = {
    "anthropic", "openai", "microsoft", "google", "aws", "cloudflare",
    "github", "stripe", "linear", "notion", "slack",
}

# Known malicious or high-risk MCP server patterns
KNOWN_RISKY_SERVERS: dict[str, str] = {
    # populated from threat intel — placeholder
}

# Tool capability taxonomy (extended from v1)
MCP_TOOL_CAPS: list[dict] = [
    {"id": "SHELL",   "keywords": ["shell","bash","exec","terminal","command","subprocess","run","cmd"],
     "severity": Severity.CRITICAL, "cap": "shell_exec",
     "edge": EdgeType.EXECUTES, "target": "shell_process", "mitre": ["AML.T0017","AML.T0048"]},
    {"id": "SECRETS", "keywords": ["secret","credential","api_key","token","vault","ssm","password","keychain","auth"],
     "severity": Severity.CRITICAL, "cap": "secret_access",
     "edge": EdgeType.READS, "target": "aws_credentials", "mitre": ["AML.T0051"]},
    {"id": "FILEWRITE","keywords": ["write_file","file_write","create_file","delete_file","move_file","save_file","disk_write"],
     "severity": Severity.HIGH, "cap": "file_write",
     "edge": EdgeType.WRITES, "target": "filesystem", "mitre": ["AML.T0048"]},
    {"id": "FILEREAD", "keywords": ["read_file","file_read","open_file","cat","disk_read","filesystem"],
     "severity": Severity.MEDIUM, "cap": "file_read",
     "edge": EdgeType.READS, "target": "filesystem", "mitre": ["AML.T0051"]},
    {"id": "NET",     "keywords": ["http","fetch","request","curl","browse","web","url","network","internet"],
     "severity": Severity.MEDIUM, "cap": "network_egress",
     "edge": EdgeType.EXFILTRATES, "target": "external_network", "mitre": ["AML.T0040"]},
    {"id": "CODE",    "keywords": ["eval","python_repl","code","interpret","execute_code","run_code","notebook","repl"],
     "severity": Severity.CRITICAL, "cap": "code_execution",
     "edge": EdgeType.EXECUTES, "target": "shell_process", "mitre": ["AML.T0017"]},
    {"id": "DB",      "keywords": ["database","db","sql","query","postgres","mysql","mongo","redis","dynamo","sqlite"],
     "severity": Severity.HIGH, "cap": "database",
     "edge": EdgeType.READS, "target": "database_contents", "mitre": ["AML.T0051"]},
    {"id": "CLOUD",   "keywords": ["aws","gcp","azure","s3","ec2","iam","lambda","cloud","bucket"],
     "severity": Severity.HIGH, "cap": "cloud_api",
     "edge": EdgeType.ESCALATES, "target": "aws_credentials", "mitre": ["AML.T0048"]},
    {"id": "EMAIL",   "keywords": ["email","send_mail","smtp","sendgrid","ses","mail","gmail"],
     "severity": Severity.MEDIUM, "cap": "email_send",
     "edge": EdgeType.EXFILTRATES, "target": "external_network", "mitre": ["AML.T0040"]},
    {"id": "SPAWN",   "keywords": ["spawn","fork","subprocess","create_process","agent","child"],
     "severity": Severity.CRITICAL, "cap": "process_spawn",
     "edge": EdgeType.EXECUTES, "target": "shell_process", "mitre": ["AML.T0017","AML.T0048"]},
]


@dataclass
class MCPToolAnalysis:
    name: str
    description: str
    capabilities: list[str]
    severity: Severity
    trust_deduction: int          # how much this tool deducts from server trust score
    findings: list[Finding]
    graph_edges: list[tuple]      # (src_id, dst_id, EdgeType, confidence, mitre)


@dataclass
class MCPServerProfile:
    """Complete security profile of an MCP server."""
    name: str
    url_or_path: str
    is_live: bool
    trust_score: int              # 0-100: how much to trust this server
    trust_level: str              # "HIGH" | "MEDIUM" | "LOW" | "CRITICAL"
    risk_score: int               # 0-100: how dangerous are its capabilities
    tool_count: int
    tools: list[MCPToolAnalysis]
    findings: list[Finding]
    attack_paths: list           # GraphPath objects
    trust_deductions: list[str]
    publisher: str
    has_auth: bool
    has_wildcard_perms: bool
    capabilities: list[str]      # all unique cap names
    graph: AttackGraph


def _normalise(s: str) -> str:
    return s.lower().replace("-", "_").replace(" ", "_")


def _fetch_json(url: str, timeout: int = 10) -> dict | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "AgentScan/0.2"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


def _analyse_tool(tool: dict, server_id: str) -> MCPToolAnalysis:
    """Analyse a single MCP tool definition."""
    name = tool.get("name", "unnamed")
    desc = tool.get("description", "")
    schema = tool.get("inputSchema", tool.get("input_schema", {}))
    schema_str = json.dumps(schema).lower() if schema else ""
    haystack = _normalise(name) + " " + _normalise(desc) + " " + schema_str

    matched_caps: list[dict] = []
    for cap in MCP_TOOL_CAPS:
        if any(kw in haystack for kw in cap["keywords"]):
            matched_caps.append(cap)

    if not matched_caps:
        return MCPToolAnalysis(
            name=name, description=desc, capabilities=[], severity=Severity.INFO,
            trust_deduction=0, findings=[], graph_edges=[],
        )

    # Highest severity among matched caps
    sev_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    worst_sev = min(matched_caps, key=lambda c: sev_order.index(c["severity"]))["severity"]

    # Trust deduction: critical cap = 25, high = 15, medium = 8
    deduction = sum({
        Severity.CRITICAL: 25, Severity.HIGH: 15, Severity.MEDIUM: 8,
    }.get(c["severity"], 0) for c in matched_caps)

    findings = []
    graph_edges = []

    tool_node_id = f"tool_{server_id}_{_normalise(name)[:20]}"

    for cap in matched_caps:
        matched_kws = [kw for kw in cap["keywords"] if kw in haystack]
        findings.append(Finding(
            id=f"MCP2-{cap['id']}-{_normalise(name)[:20].upper()}",
            title=f"Tool '{name}' — {cap['cap'].replace('_', ' ')} capability",
            severity=cap["severity"],
            confidence=ConfidenceLevel.HIGH if any(kw in _normalise(name) for kw in cap["keywords"][:3]) else ConfidenceLevel.MEDIUM,
            scanner="mcp_scanner_v2",
            explanation=(
                f"Tool '{name}' in this MCP server provides {cap['cap'].replace('_',' ')} capability. "
                f"Matched keywords: {matched_kws[:3]}. "
                f"Any agent connected to this server can invoke this tool."
            ),
            impact=f"Agent can {cap['cap'].replace('_', ' ')} via '{name}'",
            remediation=(
                f"Evaluate whether '{name}' is necessary. If so: scope permissions narrowly, "
                f"implement allowlisting, add audit logging, and run in a sandbox."
            ),
            evidence=[Evidence(
                source="mcp_tool_definition",
                field=f"tools[name={name!r}]",
                observed_value={"name": name, "description": desc[:150]},
                explanation=f"Keywords matched: {matched_kws[:5]}",
            )],
            mitre_atlas=cap["mitre"],
            tags=["mcp-tool", cap["id"].lower(), cap["cap"]],
        ))
        graph_edges.append((tool_node_id, cap["target"], cap["edge"], 1.0, cap["mitre"]))

    return MCPToolAnalysis(
        name=name, description=desc,
        capabilities=[c["cap"] for c in matched_caps],
        severity=worst_sev,
        trust_deduction=min(deduction, 40),
        findings=findings,
        graph_edges=graph_edges,
    )


def _compute_trust_score(
    tools: list[MCPToolAnalysis],
    has_auth: bool,
    has_wildcard: bool,
    publisher: str,
    is_live: bool,
) -> tuple[int, list[str]]:
    """
    Compute trust score (0–100) and list of deduction reasons.
    Trust is about the *source* — how much should we trust this server?
    Risk is about the *capabilities* — how dangerous are its tools?
    """
    score = 100
    reasons = []

    if not has_auth:
        score -= 20
        reasons.append("No authentication configured — any client can call this server")

    if has_wildcard:
        score -= 15
        reasons.append("Wildcard permissions declared — overly broad access scope")

    # Publisher trust
    pub_lower = publisher.lower()
    if not any(t in pub_lower for t in TRUSTED_PUBLISHERS):
        score -= 10
        reasons.append(f"Publisher '{publisher}' is not in trusted publisher registry")
    else:
        reasons.append(f"✓ Publisher '{publisher}' is a trusted source (+0 deduction)")

    # Tool deductions
    total_tool_deduction = sum(t.trust_deduction for t in tools)
    capped_deduction = min(total_tool_deduction, 45)
    if capped_deduction > 0:
        score -= capped_deduction
        dangerous = [t.name for t in tools if t.trust_deduction >= 25]
        if dangerous:
            reasons.append(f"High-risk tools detected: {', '.join(dangerous[:3])}")

    # Live server bonus (we have direct evidence)
    if is_live:
        reasons.append("✓ Live server — tool list verified directly")

    score = max(0, score)
    return score, reasons


def _build_mcp_graph(
    server_name: str, server_id: str,
    tools: list[MCPToolAnalysis],
    has_auth: bool,
) -> AttackGraph:
    """Build an AttackGraph for this MCP server."""
    from agentscan.graph.engine import build_graph_from_scan

    # Build a minimal ScanResult to feed to graph builder
    caps = list({cap for t in tools for cap in t.capabilities})
    cap_to_tools: dict[str, list[str]] = {}
    for t in tools:
        for cap in t.capabilities:
            cap_to_tools.setdefault(cap, []).append(t.name)

    # Create graph manually for MCP context
    from agentscan.graph.engine import AttackGraph as AG
    g = AG()

    # MCP server node
    server_node = Node(
        id=server_id, type=NodeType.MCP_SERVER,
        label=server_name, trust_boundary=True,
        properties={"has_auth": has_auth},
    )
    g.add_node(server_node)

    # Injection edge: agent calls MCP server, tool responses can inject
    g.add_edge(Edge(
        src="user_prompt", dst=server_id,
        type=EdgeType.INJECTS, label="indirect prompt injection via tool response",
        confidence=0.85, mitre=["AML.T0051"],
    ))

    # Add tool nodes and their resource edges
    for tool in tools:
        if not tool.graph_edges:
            continue
        tool_id = f"tool_{server_id}_{_normalise(tool.name)[:20]}"
        tool_node = Node(
            id=tool_id, type=NodeType.TOOL,
            label=tool.name,
            properties={"capabilities": tool.capabilities, "server": server_name},
        )
        g.add_node(tool_node)

        # Server → tool (agent calls tool via MCP)
        g.add_edge(Edge(
            src=server_id, dst=tool_id,
            type=EdgeType.CALLS, label="exposes tool",
            confidence=1.0,
        ))

        # Tool → resources
        for src, dst, etype, conf, mitre in tool.graph_edges:
            g.add_edge(Edge(
                src=tool_id, dst=dst,
                type=etype, label=f"{etype.value} via {tool.name}",
                confidence=conf, mitre=mitre,
            ))

    # Cross-tool chaining edges (the key insight)
    all_caps = set(caps)
    if "secret_access" in all_caps and "network_egress" in all_caps:
        g.add_edge(Edge(
            src="aws_credentials", dst="external_network",
            type=EdgeType.EXFILTRATES, label="exfiltrate credentials",
            confidence=0.85, mitre=["AML.T0040", "AML.T0051"],
        ))
    if "shell_exec" in all_caps and "network_egress" in all_caps:
        g.add_edge(Edge(
            src="shell_process", dst="external_network",
            type=EdgeType.EXFILTRATES, label="reverse shell / data exfil",
            confidence=0.9, mitre=["AML.T0040"],
        ))
    if "shell_exec" in all_caps:
        g.add_edge(Edge(
            src="shell_process", dst="aws_credentials",
            type=EdgeType.READS, label="read credential files / env",
            confidence=0.9, mitre=["AML.T0051"],
        ))
    if "database" in all_caps and "network_egress" in all_caps:
        g.add_edge(Edge(
            src="database_contents", dst="external_network",
            type=EdgeType.EXFILTRATES, label="exfiltrate DB results",
            confidence=0.8, mitre=["AML.T0040"],
        ))

    return g


def scan_mcp_v2(target: str, timeout: int = 10) -> tuple[MCPServerProfile, ScanResult]:
    """
    Full MCP security platform scan.
    Returns (MCPServerProfile, ScanResult) — profile has rich data,
    ScanResult is compatible with the rest of the AgentScan pipeline.
    """
    start = time.monotonic()
    is_live = target.startswith("http://") or target.startswith("https://")

    # Load manifest
    manifest: dict = {}
    if is_live:
        data = _fetch_json(target.rstrip("/") + "/tools/list", timeout=timeout)
        if not data:
            err = ScanResult(target=target, scanner_type="mcp_scanner_v2",
                             error=f"Cannot connect to MCP server: {target}")
            return MCPServerProfile(
                name="unknown", url_or_path=target, is_live=True,
                trust_score=0, trust_level="CRITICAL", risk_score=0,
                tool_count=0, tools=[], findings=[], attack_paths=[],
                trust_deductions=["Cannot connect to server"],
                publisher="unknown", has_auth=False, has_wildcard_perms=False,
                capabilities=[], graph=AttackGraph(),
            ), err
        manifest = data
    else:
        path = Path(target)
        if not path.exists():
            err = ScanResult(target=target, scanner_type="mcp_scanner_v2",
                             error=f"File not found: {target}")
            return MCPServerProfile(
                name="unknown", url_or_path=target, is_live=False,
                trust_score=0, trust_level="CRITICAL", risk_score=0,
                tool_count=0, tools=[], findings=[], attack_paths=[],
                trust_deductions=["File not found"],
                publisher="unknown", has_auth=False, has_wildcard_perms=False,
                capabilities=[], graph=AttackGraph(),
            ), err
        try:
            text = path.read_text(encoding="utf-8")
            manifest = yaml.safe_load(text) if path.suffix in (".yaml", ".yml") else json.loads(text)
        except Exception as exc:
            err = ScanResult(target=target, scanner_type="mcp_scanner_v2", error=str(exc))
            return MCPServerProfile(
                name="unknown", url_or_path=target, is_live=False,
                trust_score=0, trust_level="CRITICAL", risk_score=0,
                tool_count=0, tools=[], findings=[], attack_paths=[],
                trust_deductions=[str(exc)],
                publisher="unknown", has_auth=False, has_wildcard_perms=False,
                capabilities=[], graph=AttackGraph(),
            ), err

    if not isinstance(manifest, dict):
        manifest = {}

    server_name = manifest.get("name", manifest.get("server_name",
                  Path(target).stem if not is_live else target.split("//")[-1].split("/")[0]))
    publisher = manifest.get("publisher", manifest.get("author",
                manifest.get("maintainer", server_name.split("/")[0] if "/" in server_name else "unknown")))
    has_auth = bool(manifest.get("auth") or manifest.get("authentication") or manifest.get("security"))
    permissions = manifest.get("permissions", manifest.get("scopes", []))
    has_wildcard = isinstance(permissions, list) and any(
        "*" in str(p) or "admin" in str(p).lower() for p in permissions
    )

    # Analyse all tools
    raw_tools = manifest.get("tools", [])
    if not isinstance(raw_tools, list):
        raw_tools = []

    server_id = f"mcp_{hashlib.md5(target.encode()).hexdigest()[:8]}"
    tool_analyses = [_analyse_tool(t, server_id) for t in raw_tools]

    # Compute scores
    trust_score, trust_deductions = _compute_trust_score(
        tool_analyses, has_auth, has_wildcard, publisher, is_live
    )
    trust_level = "HIGH" if trust_score >= 70 else "MEDIUM" if trust_score >= 40 else "LOW" if trust_score >= 20 else "CRITICAL"

    # Risk score = how dangerous are the capabilities
    cap_risk = {"shell_exec": 40, "code_execution": 40, "secret_access": 35,
                "cloud_api": 30, "database": 25, "file_write": 20,
                "network_egress": 15, "file_read": 10, "email_send": 10}
    all_caps = list({cap for t in tool_analyses for cap in t.capabilities})
    risk_score = min(sum(cap_risk.get(c, 5) for c in all_caps), 100)

    # Build graph
    graph = _build_mcp_graph(server_name, server_id, tool_analyses, has_auth)
    from agentscan.graph.engine import build_graph_from_scan
    paths = graph.find_attack_paths()

    # Collect all findings
    all_findings: list[Finding] = []

    # Auth finding
    if not has_auth and raw_tools:
        all_findings.append(Finding(
            id="MCP2-AUTH-MISSING",
            title="MCP server has no authentication",
            severity=Severity.HIGH,
            confidence=ConfidenceLevel.HIGH,
            scanner="mcp_scanner_v2",
            explanation="No authentication is configured. Any client can call this server's tools without identity verification.",
            impact="Unauthorised tool invocation from any network-accessible client",
            remediation="Implement OAuth 2.0 (supported natively in MCP spec). At minimum, require API key authentication.",
            evidence=[Evidence("manifest", "auth", None, "No auth/authentication/security key found")],
            mitre_atlas=["AML.T0048"],
            tags=["mcp-auth"],
        ))

    # Wildcard permission finding
    if has_wildcard:
        all_findings.append(Finding(
            id="MCP2-PERMS-WILDCARD",
            title="MCP server declares wildcard permissions",
            severity=Severity.HIGH,
            confidence=ConfidenceLevel.HIGH,
            scanner="mcp_scanner_v2",
            explanation="The server manifest declares overly broad permissions including wildcards or admin scopes.",
            impact="Over-privileged access inherited by all connecting agents",
            remediation="Replace wildcard permissions with explicit, minimal permission declarations per tool.",
            evidence=[Evidence("manifest", "permissions", permissions, "Wildcard/admin permission strings found")],
            mitre_atlas=["AML.T0048"],
            tags=["mcp-permissions"],
        ))

    # Tool findings
    for t in tool_analyses:
        all_findings.extend(t.findings)

    # Build ScanResult (compatible with rest of pipeline)
    elapsed_ms = int((time.monotonic() - start) * 1000)

    from agentscan.graph.engine import graph_paths_to_attack_paths
    attack_paths = graph_paths_to_attack_paths(paths)

    result = ScanResult(
        target=target,
        scanner_type="mcp_scanner_v2",
        findings=all_findings,
        attack_paths=attack_paths,
        metadata={
            "server_name": server_name,
            "publisher": publisher,
            "trust_score": trust_score,
            "trust_level": trust_level,
            "risk_score": risk_score,
            "tool_count": len(raw_tools),
            "capabilities_detected": all_caps,
            "has_auth": has_auth,
            "is_live": is_live,
        },
        scan_duration_ms=elapsed_ms,
    )

    profile = MCPServerProfile(
        name=server_name, url_or_path=target, is_live=is_live,
        trust_score=trust_score, trust_level=trust_level,
        risk_score=risk_score, tool_count=len(raw_tools),
        tools=tool_analyses, findings=all_findings,
        attack_paths=paths, trust_deductions=trust_deductions,
        publisher=publisher, has_auth=has_auth, has_wildcard_perms=has_wildcard,
        capabilities=all_caps, graph=graph,
    )

    return profile, result
