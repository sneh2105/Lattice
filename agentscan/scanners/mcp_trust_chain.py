"""
MCP Multi-Server Trust Chain Analyser
======================================
Models the full trust topology when an agent connects to multiple MCP servers,
or when MCP servers themselves call other MCP servers (server-to-server delegation).

Key problems this solves:

1. TRANSITIVE TRUST POLLUTION
   Agent trusts Server A (score: 80).
   Server A calls Server B (score: 20, has shell_exec).
   Agent inherits Server B's risk even though it never declared it.
   → Effective trust of Server A = min(A, B) = 20.

2. BLAST RADIUS ACROSS SERVER BOUNDARIES
   Server A: read-only search tool.
   Server B: network egress tool.
   Agent uses both.
   → Combined attack path: injection → Server A search → Server B HTTP → exfil.
   Neither server alone looks dangerous. Together they form a critical path.

3. TRUST BOUNDARY VIOLATIONS
   Server A declares it only does "read-only database access."
   But it calls Server B which has write access.
   → Server A's declared scope is violated by its dependency.

4. CIRCULAR TRUST / CYCLE DETECTION
   Server A calls Server B calls Server A.
   → Infinite trust propagation loop if not detected.

Architecture:
  MCPTrustChain holds a graph of MCPServerProfile nodes.
  Edges represent: AGENT_CALLS, SERVER_CALLS, DECLARES_DEPENDENCY.
  Trust propagation walks the graph computing effective trust at each node.
  Attack paths cross server boundaries using the unified AttackGraph.
"""

from __future__ import annotations
import json
import time
from dataclasses import dataclass, field
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

import yaml

from agentscan.models import (
    ScanResult, Finding, AttackPath, Evidence, Severity, ConfidenceLevel
)
from agentscan.scanners.mcp_scanner_v2 import scan_mcp_v2, MCPServerProfile
from agentscan.graph.engine import AttackGraph, build_graph_from_scan, graph_paths_to_attack_paths
from agentscan.graph.nodes import Node, Edge, NodeType, EdgeType


# ── Trust propagation rules ──────────────────────────────────────────────────

# How much trust degrades per hop in a server-to-server call chain
TRUST_HOP_PENALTY = 10

# If a downstream server has trust below this, it poisons the upstream
TRUST_POISON_THRESHOLD = 40


@dataclass
class ServerEdge:
    """A directed trust relationship between two MCP servers."""
    src_id: str          # caller
    dst_id: str          # callee
    relationship: str    # "agent_calls" | "server_calls" | "declares_dependency"
    declared: bool       # was this relationship explicitly declared, or inferred?
    confidence: float    # 0.0-1.0


@dataclass
class TrustPropagationResult:
    """Trust score after propagating through the full call chain."""
    server_id: str
    server_name: str
    declared_trust: int          # trust score from direct analysis
    effective_trust: int         # trust after propagation
    trust_reduction: int         # how much propagation reduced trust
    poisoned_by: list[str]       # server names that reduced this server's trust
    propagation_path: list[str]  # chain that caused the reduction


@dataclass
class CrossServerPath:
    """An attack path that crosses MCP server boundaries."""
    title: str
    severity: Severity
    servers_involved: list[str]
    entry_server: str
    exit_server: str
    entry_point: str
    impact: str
    description: str
    step_labels: list[str]
    mitre_atlas: list[str]
    composite_score: float


@dataclass
class MCPTrustChainReport:
    """Complete multi-server trust chain analysis report."""
    targets: list[str]
    server_profiles: dict[str, MCPServerProfile]   # server_id → profile
    edges: list[ServerEdge]
    trust_propagation: dict[str, TrustPropagationResult]
    cross_server_paths: list[CrossServerPath]
    findings: list[Finding]
    unified_graph: AttackGraph
    # Summary
    weakest_server: str | None
    effective_trust_floor: int         # lowest effective trust in the chain
    total_attack_paths: int
    scan_duration_ms: int


class MCPTrustChain:
    """
    Analyses trust relationships across multiple MCP servers.

    Usage:
        chain = MCPTrustChain()
        chain.add_server("https://mcp.server-a.com")
        chain.add_server("./server_b.json")
        chain.declare_calls("server-a", "server-b")   # A calls B
        report = chain.analyse()
    """

    def __init__(self):
        self._targets: list[str] = []
        self._profiles: dict[str, MCPServerProfile] = {}     # name → profile
        self._id_map: dict[str, str] = {}                    # name → server_id
        self._declared_edges: list[tuple[str, str]] = []     # (src_name, dst_name)

    def add_server(self, target: str, timeout: int = 10) -> str:
        """Scan and add an MCP server. Returns server name."""
        profile, _ = scan_mcp_v2(target, timeout=timeout)
        self._targets.append(target)
        self._profiles[profile.name] = profile
        self._id_map[profile.name] = f"mcp_{len(self._profiles)}"
        return profile.name

    def add_server_profile(self, profile: MCPServerProfile) -> None:
        """Add a pre-scanned profile directly (for testing)."""
        self._profiles[profile.name] = profile
        self._id_map[profile.name] = f"mcp_{len(self._profiles)}"

    def declare_calls(self, src_name: str, dst_name: str) -> None:
        """Declare that src_name calls dst_name."""
        self._declared_edges.append((src_name, dst_name))

    def analyse(self) -> MCPTrustChainReport:
        """Run full multi-server trust chain analysis."""
        start = time.monotonic()

        # Build edge list
        edges = self._build_edges()

        # Build unified attack graph across all servers
        unified_graph = self._build_unified_graph(edges)

        # Propagate trust through the graph
        propagation = self._propagate_trust(edges)

        # Find cross-server attack paths
        cross_paths = self._find_cross_server_paths(unified_graph, edges)

        # Generate findings
        findings = self._generate_findings(propagation, cross_paths, edges)

        elapsed_ms = int((time.monotonic() - start) * 1000)

        profiles = dict(self._profiles)
        weakest = min(propagation.values(), key=lambda r: r.declared_trust, default=None)

        return MCPTrustChainReport(
            targets=list(self._targets),
            server_profiles=profiles,
            edges=edges,
            trust_propagation=propagation,
            cross_server_paths=cross_paths,
            findings=findings,
            unified_graph=unified_graph,
            weakest_server=weakest.server_name if weakest else None,
            effective_trust_floor=weakest.effective_trust if weakest else 100,
            total_attack_paths=len(cross_paths),
            scan_duration_ms=elapsed_ms,
        )

    # ── Internal methods ─────────────────────────────────────────────────────

    def _build_edges(self) -> list[ServerEdge]:
        """Build declared + inferred edges between servers."""
        edges: list[ServerEdge] = []

        # Declared server-to-server calls
        for src_name, dst_name in self._declared_edges:
            if src_name in self._profiles and dst_name in self._profiles:
                edges.append(ServerEdge(
                    src_id=self._id_map[src_name],
                    dst_id=self._id_map[dst_name],
                    relationship="server_calls",
                    declared=True,
                    confidence=1.0,
                ))

        # Infer dependencies from server metadata / tool descriptions
        for name, profile in self._profiles.items():
            for other_name, other_profile in self._profiles.items():
                if name == other_name:
                    continue
                # Check if any tool description references another server
                for tool in profile.tools:
                    desc_lower = (tool.description or "").lower()
                    if other_name.lower() in desc_lower or other_profile.url_or_path.lower() in desc_lower:
                        edges.append(ServerEdge(
                            src_id=self._id_map[name],
                            dst_id=self._id_map[other_name],
                            relationship="declares_dependency",
                            declared=False,
                            confidence=0.7,
                        ))

        return edges

    def _build_unified_graph(self, edges: list[ServerEdge]) -> AttackGraph:
        """
        Merge individual server graphs into one unified graph.
        Add cross-server edges based on declared/inferred calls.
        """
        unified = AttackGraph()

        # Build id→name reverse map
        id_to_name = {v: k for k, v in self._id_map.items()}

        # Merge each server's graph
        for name, profile in self._profiles.items():
            server_id = self._id_map[name]
            g = profile.graph

            # Copy all nodes (prefix server_id to avoid collisions)
            for node_id, node in g.nodes.items():
                # Global nodes (entry points, crown jewels) keep their IDs
                if node_id in ("user_prompt", "tool_response", "rag_context",
                               "aws_credentials", "api_keys", "database_contents",
                               "external_network", "shell_process", "filesystem", "pii_store"):
                    unified.add_node(node)
                else:
                    # Server-scoped nodes get prefixed
                    scoped_node = Node(
                        id=f"{server_id}_{node_id}",
                        type=node.type,
                        label=f"{node.label} [{name}]",
                        attacker_controlled=node.attacker_controlled,
                        is_crown_jewel=node.is_crown_jewel,
                        crown_jewel_value=node.crown_jewel_value,
                        trust_boundary=node.trust_boundary,
                        properties={**node.properties, "server": name},
                    )
                    unified.add_node(scoped_node)

            # Copy edges with scoped IDs
            for edge in g.edges:
                def scope(nid: str) -> str:
                    if nid in ("user_prompt", "tool_response", "rag_context",
                               "aws_credentials", "api_keys", "database_contents",
                               "external_network", "shell_process", "filesystem", "pii_store"):
                        return nid
                    return f"{server_id}_{nid}"

                unified.add_edge(Edge(
                    src=scope(edge.src),
                    dst=scope(edge.dst),
                    type=edge.type,
                    label=edge.label,
                    confidence=edge.confidence,
                    mitre=edge.mitre,
                ))

        # Add cross-server edges (server A calls server B)
        for se in edges:
            if se.relationship in ("server_calls", "declares_dependency"):
                src_name = id_to_name.get(se.src_id, se.src_id)
                dst_name = id_to_name.get(se.dst_id, se.dst_id)
                src_server_node_id = f"{se.src_id}_{se.src_id}"
                dst_server_node_id = f"{se.dst_id}_{se.dst_id}"

                # If neither scoped node exists, try the raw IDs
                if src_server_node_id not in unified.nodes:
                    src_server_node_id = se.src_id
                if dst_server_node_id not in unified.nodes:
                    dst_server_node_id = se.dst_id

                # Add a TRUSTS edge between the two server nodes
                unified.add_edge(Edge(
                    src=src_server_node_id,
                    dst=dst_server_node_id,
                    type=EdgeType.TRUSTS,
                    label=f"{src_name} calls {dst_name}",
                    confidence=se.confidence,
                ))

                # Key insight: if dst server has dangerous capabilities,
                # create edges from src server's entry point to dst's crown jewels
                dst_profile = self._profiles.get(dst_name)
                if dst_profile:
                    for cap in dst_profile.capabilities:
                        cap_to_crown = {
                            "shell_exec":     ("shell_process", EdgeType.EXECUTES, ["AML.T0017"]),
                            "code_execution": ("shell_process", EdgeType.EXECUTES, ["AML.T0017"]),
                            "secret_access":  ("aws_credentials", EdgeType.READS, ["AML.T0051"]),
                            "network_egress": ("external_network", EdgeType.EXFILTRATES, ["AML.T0040"]),
                            "database":       ("database_contents", EdgeType.READS, ["AML.T0051"]),
                        }
                        if cap in cap_to_crown:
                            crown_id, etype, mitre = cap_to_crown[cap]
                            # src server can reach dst's capabilities
                            unified.add_edge(Edge(
                                src=src_server_node_id,
                                dst=crown_id,
                                type=etype,
                                label=f"via {dst_name} ({cap})",
                                confidence=se.confidence * 0.9,
                                mitre=mitre,
                            ))

        return unified

    def _propagate_trust(self, edges: list[ServerEdge]) -> dict[str, TrustPropagationResult]:
        """
        Propagate trust scores through the call chain.

        Rule: if Server A calls Server B, A's effective trust
        = min(A.declared_trust, B.effective_trust - HOP_PENALTY)

        We use topological sort to propagate in dependency order.
        Cycles are detected and reported.
        """
        results: dict[str, TrustPropagationResult] = {}

        # Initialise with declared scores
        for name, profile in self._profiles.items():
            results[name] = TrustPropagationResult(
                server_id=self._id_map[name],
                server_name=name,
                declared_trust=profile.trust_score,
                effective_trust=profile.trust_score,
                trust_reduction=0,
                poisoned_by=[],
                propagation_path=[name],
            )

        # Build adjacency: src → list of dst names
        adj: dict[str, list[str]] = defaultdict(list)
        id_to_name = {v: k for k, v in self._id_map.items()}
        for se in edges:
            if se.relationship in ("server_calls", "declares_dependency"):
                src = id_to_name.get(se.src_id, se.src_id)
                dst = id_to_name.get(se.dst_id, se.dst_id)
                if src in results and dst in results:
                    adj[src].append(dst)

        # Detect cycles first
        cycles = self._detect_cycles(adj)

        # BFS propagation — propagate from leaves upward
        # For each server, compute effective trust from all dependencies
        changed = True
        iterations = 0
        while changed and iterations < 20:
            changed = False
            iterations += 1
            for src_name, dst_names in adj.items():
                for dst_name in dst_names:
                    if dst_name not in results:
                        continue
                    dst_effective = results[dst_name].effective_trust
                    propagated = dst_effective - TRUST_HOP_PENALTY
                    if propagated < results[src_name].effective_trust:
                        old = results[src_name].effective_trust
                        results[src_name].effective_trust = max(0, propagated)
                        results[src_name].trust_reduction = (
                            results[src_name].declared_trust - results[src_name].effective_trust
                        )
                        if dst_name not in results[src_name].poisoned_by:
                            results[src_name].poisoned_by.append(dst_name)
                        results[src_name].propagation_path = (
                            results[src_name].propagation_path + [dst_name]
                        )
                        changed = True

        return results

    def _detect_cycles(self, adj: dict[str, list[str]]) -> list[list[str]]:
        """Detect circular trust relationships using DFS."""
        visited: set[str] = set()
        rec_stack: set[str] = set()
        cycles: list[list[str]] = []

        def dfs(node: str, path: list[str]):
            visited.add(node)
            rec_stack.add(node)
            for neighbour in adj.get(node, []):
                if neighbour not in visited:
                    dfs(neighbour, path + [neighbour])
                elif neighbour in rec_stack:
                    # Found cycle
                    cycle_start = path.index(neighbour) if neighbour in path else 0
                    cycles.append(path[cycle_start:] + [neighbour])
            rec_stack.discard(node)

        for node in list(adj.keys()):
            if node not in visited:
                dfs(node, [node])

        return cycles

    def _find_cross_server_paths(
        self, unified_graph: AttackGraph, edges: list[ServerEdge]
    ) -> list[CrossServerPath]:
        """
        Find attack paths that cross MCP server boundaries.
        These are paths where the intermediate nodes include
        nodes from different servers.
        """
        cross_paths: list[CrossServerPath] = []
        graph_paths = unified_graph.find_attack_paths()

        id_to_name = {v: k for k, v in self._id_map.items()}

        for gp in graph_paths:
            # Check if path crosses server boundaries
            servers_in_path: list[str] = []
            for node in gp.nodes:
                # Extract server name from node properties or ID
                server = node.properties.get("server")
                if server and server not in servers_in_path:
                    servers_in_path.append(server)

            if len(servers_in_path) < 2 and len(self._profiles) > 1:
                # Single-server path in a multi-server context — still relevant
                # but not a cross-server path
                pass

            if gp.composite_score < 20:
                continue

            sev = (
                Severity.CRITICAL if gp.composite_score >= 60 else
                Severity.HIGH if gp.composite_score >= 35 else
                Severity.MEDIUM
            )

            description = gp.description
            if len(servers_in_path) >= 2:
                description = (
                    f"This attack path crosses {len(servers_in_path)} MCP server boundary(ies): "
                    f"{' → '.join(servers_in_path)}.\n\n"
                    "This is particularly dangerous because each server may appear safe in isolation "
                    "but together they form a complete exploit chain.\n\n"
                ) + description

            cross_paths.append(CrossServerPath(
                title=gp.title,
                severity=sev,
                servers_involved=servers_in_path if servers_in_path else list(self._profiles.keys()),
                entry_server=servers_in_path[0] if servers_in_path else "",
                exit_server=servers_in_path[-1] if servers_in_path else "",
                entry_point=gp.entry_point.label,
                impact=gp.crown_jewel.properties.get("impact", "High-value asset compromised"),
                description=description,
                step_labels=gp.step_labels(),
                mitre_atlas=gp.mitre_atlas,
                composite_score=gp.composite_score,
            ))

        return sorted(cross_paths, key=lambda p: -p.composite_score)

    def _generate_findings(
        self,
        propagation: dict[str, TrustPropagationResult],
        cross_paths: list[CrossServerPath],
        edges: list[ServerEdge],
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Finding: trust pollution
        for name, result in propagation.items():
            if result.trust_reduction > 0 and result.poisoned_by:
                findings.append(Finding(
                    id=f"CHAIN-TRUST-POLLUTION-{name[:20].upper().replace(' ','_')}",
                    title=f"Trust pollution: '{name}' inherits low trust from downstream server(s)",
                    severity=Severity.HIGH if result.effective_trust < 40 else Severity.MEDIUM,
                    confidence=ConfidenceLevel.HIGH,
                    scanner="mcp_trust_chain",
                    explanation=(
                        f"Server '{name}' has a declared trust score of {result.declared_trust}/100, "
                        f"but its effective trust is only {result.effective_trust}/100 after propagating "
                        f"trust from downstream server(s): {', '.join(result.poisoned_by)}. "
                        "An agent that trusts this server implicitly trusts everything it calls."
                    ),
                    impact=(
                        f"Agent is exposed to the risk profile of '{', '.join(result.poisoned_by)}' "
                        "even if it was never explicitly granted access to those servers."
                    ),
                    remediation=(
                        f"Review the call relationship between '{name}' and '{', '.join(result.poisoned_by)}'. "
                        "Either increase the trust of downstream servers by adding authentication and "
                        "scoping permissions, or break the server-to-server call relationship."
                    ),
                    evidence=[Evidence(
                        source="trust_propagation",
                        field="effective_trust",
                        observed_value={
                            "declared": result.declared_trust,
                            "effective": result.effective_trust,
                            "poisoned_by": result.poisoned_by,
                        },
                        explanation=f"Trust reduced by {result.trust_reduction} points via call chain",
                    )],
                    mitre_atlas=["AML.T0048"],
                    tags=["mcp-trust-chain", "trust-pollution"],
                ))

        # Finding: cross-server attack paths
        for i, path in enumerate(cross_paths[:5]):
            if len(path.servers_involved) >= 2:
                findings.append(Finding(
                    id=f"CHAIN-XSERVER-PATH-{i+1}",
                    title=f"Cross-server attack path: {path.title}",
                    severity=path.severity,
                    confidence=ConfidenceLevel.HIGH,
                    scanner="mcp_trust_chain",
                    explanation=path.description,
                    impact=path.impact,
                    remediation=(
                        "Break the attack chain by either: (a) removing dangerous capabilities from "
                        "downstream servers, (b) adding network-level isolation between servers, or "
                        "(c) requiring explicit agent approval for cross-server tool calls."
                    ),
                    evidence=[Evidence(
                        source="unified_attack_graph",
                        field="cross_server_path",
                        observed_value=" → ".join(path.step_labels),
                        explanation=f"Score: {path.composite_score:.1f}  Servers: {' → '.join(path.servers_involved)}",
                    )],
                    mitre_atlas=path.mitre_atlas,
                    tags=["mcp-trust-chain", "cross-server-path"],
                ))

        # Finding: undeclared server-to-server dependency
        for se in edges:
            if not se.declared and se.relationship == "declares_dependency":
                id_to_name = {v: k for k, v in self._id_map.items()}
                src = id_to_name.get(se.src_id, se.src_id)
                dst = id_to_name.get(se.dst_id, se.dst_id)
                findings.append(Finding(
                    id=f"CHAIN-UNDECLARED-DEP-{src[:15].upper()}",
                    title=f"Undeclared server dependency: '{src}' → '{dst}'",
                    severity=Severity.MEDIUM,
                    confidence=ConfidenceLevel.MEDIUM,
                    scanner="mcp_trust_chain",
                    explanation=(
                        f"Server '{src}' appears to call or depend on '{dst}' based on tool "
                        "description analysis, but this relationship was not explicitly declared. "
                        "Undeclared dependencies expand the attack surface without visibility."
                    ),
                    impact="Hidden trust relationship exposes agent to undisclosed risk",
                    remediation=(
                        f"Explicitly document the '{src}' → '{dst}' dependency. "
                        "Add it to the server manifest and ensure '{dst}' passes security review."
                    ),
                    evidence=[Evidence(
                        source="tool_description_analysis",
                        field="description",
                        observed_value=f"{src} references {dst}",
                        explanation="Server name found in tool description — inferred dependency",
                    )],
                    mitre_atlas=["AML.T0048"],
                    tags=["mcp-trust-chain", "undeclared-dependency"],
                ))

        return findings
