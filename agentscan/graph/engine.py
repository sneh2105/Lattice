# -*- coding: utf-8 -*-
"""
AI Attack Graph Engine
======================
Builds a directed graph of nodes (tools, resources, entry points, crown jewels)
and edges (data flows, execution paths, trust relationships), then runs:

  1. Reachability analysis   -- from each attacker-controlled entry point,
                               what crown jewels are reachable?
  2. Path finding            -- shortest + most dangerous paths to each crown jewel
  3. Blast radius scoring    -- weighted sum of reachable crown jewel values
  4. Attack path ranking     -- ordered by exploitability x impact

This is the Wiz-inspired insight: don't report individual findings,
report the complete chains from attacker input to high-value impact.
"""

from __future__ import annotations
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

from agentscan.graph.nodes import (
    Node, Edge, NodeType, EdgeType,
    ATTACKER_ENTRY_NODES, CROWN_JEWEL_NODES,
    CROWN_JEWEL_VALUE,
)
from agentscan.models import ScanResult, Severity, AttackPath, Finding, Evidence, ConfidenceLevel


@dataclass
class GraphPath:
    """A complete path through the graph from entry point to crown jewel."""
    nodes: list[Node]
    edges: list[Edge]
    entry_point: Node
    crown_jewel: Node
    # Scoring
    exploitability: float   # 0-1: how easy is this to exploit?
    impact: int             # 0-100: crown jewel value
    composite_score: float  # exploitability x impact
    # Narrative
    title: str
    description: str
    mitre_atlas: list[str] = field(default_factory=list)

    def step_labels(self) -> list[str]:
        return [n.label for n in self.nodes]


class AttackGraph:
    """
    Directed graph of the agent's attack surface.

    Build it by calling:
        g = AttackGraph()
        g.add_node(...)
        g.add_edge(...)
        paths = g.find_attack_paths()
    """

    def __init__(self):
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []
        self._adj: dict[str, list[Edge]] = defaultdict(list)   # adjacency list
        self._radj: dict[str, list[Edge]] = defaultdict(list)  # reverse adjacency

        # Add always-present nodes
        for node in ATTACKER_ENTRY_NODES.values():
            self.add_node(node)
        for node in CROWN_JEWEL_NODES.values():
            self.add_node(node)

    def add_node(self, node: Node) -> None:
        self.nodes[node.id] = node

    def add_edge(self, edge: Edge) -> None:
        self.edges.append(edge)
        self._adj[edge.src].append(edge)
        self._radj[edge.dst].append(edge)

    def get_node(self, node_id: str) -> Node | None:
        return self.nodes.get(node_id)

    # -- Reachability --------------------------------------------------------

    def reachable_from(self, start_id: str, min_confidence: float = 0.5) -> set[str]:
        """BFS: all node IDs reachable from start_id."""
        visited: set[str] = set()
        queue = deque([start_id])
        while queue:
            current = queue.popleft()
            if current in visited:
                continue
            visited.add(current)
            for edge in self._adj.get(current, []):
                if edge.confidence >= min_confidence and edge.dst not in visited:
                    queue.append(edge.dst)
        return visited

    def shortest_path(self, start_id: str, end_id: str, min_confidence: float = 0.5) -> list[str] | None:
        """BFS shortest path. Returns list of node IDs or None."""
        if start_id not in self.nodes or end_id not in self.nodes:
            return None
        queue = deque([[start_id]])
        visited: set[str] = {start_id}
        while queue:
            path = queue.popleft()
            current = path[-1]
            if current == end_id:
                return path
            for edge in self._adj.get(current, []):
                if edge.confidence >= min_confidence and edge.dst not in visited:
                    visited.add(edge.dst)
                    queue.append(path + [edge.dst])
        return None

    def all_paths(self, start_id: str, end_id: str,
                  max_depth: int = 8, min_confidence: float = 0.5) -> list[list[str]]:
        """DFS all simple paths from start to end (capped at max_depth)."""
        results: list[list[str]] = []

        def dfs(current: str, path: list[str], visited: set[str]):
            if len(path) > max_depth:
                return
            if current == end_id:
                results.append(list(path))
                return
            for edge in self._adj.get(current, []):
                if edge.confidence >= min_confidence and edge.dst not in visited:
                    visited.add(edge.dst)
                    path.append(edge.dst)
                    dfs(edge.dst, path, visited)
                    path.pop()
                    visited.discard(edge.dst)

        dfs(start_id, [start_id], {start_id})
        return results

    def _path_edges(self, node_path: list[str]) -> list[Edge]:
        """Retrieve edges for a node-id path."""
        edges = []
        edge_lookup: dict[tuple, Edge] = {(e.src, e.dst): e for e in self.edges}
        for i in range(len(node_path) - 1):
            e = edge_lookup.get((node_path[i], node_path[i+1]))
            if e:
                edges.append(e)
        return edges

    # -- Path finding --------------------------------------------------------

    def find_attack_paths(self, min_confidence: float = 0.5) -> list[GraphPath]:
        """
        Find all paths from attacker-controlled entry points to crown jewels.
        Returns paths sorted by composite score (exploitability x impact).
        """
        paths: list[GraphPath] = []
        entry_ids = [nid for nid, n in self.nodes.items() if n.attacker_controlled]
        crown_ids = [nid for nid, n in self.nodes.items() if n.is_crown_jewel or n.crown_jewel_value > 50]

        for entry_id in entry_ids:
            reachable = self.reachable_from(entry_id, min_confidence)
            for crown_id in crown_ids:
                if crown_id not in reachable or crown_id == entry_id:
                    continue
                # Find the shortest path (for display)
                node_path = self.shortest_path(entry_id, crown_id, min_confidence)
                if not node_path or len(node_path) < 2:
                    continue

                node_objs = [self.nodes[nid] for nid in node_path if nid in self.nodes]
                edge_objs = self._path_edges(node_path)

                entry_node = self.nodes[entry_id]
                crown_node = self.nodes[crown_id]

                # Score the path
                exploitability = _score_exploitability(node_objs, edge_objs)
                impact = crown_node.crown_jewel_value or 50
                composite = exploitability * impact

                # Collect MITRE ATLAS from all edges
                mitre: list[str] = []
                for e in edge_objs:
                    mitre.extend(e.mitre)
                mitre = sorted(set(mitre))

                # Build narrative
                title, description = _build_narrative(entry_node, crown_node, node_objs, edge_objs)

                paths.append(GraphPath(
                    nodes=node_objs,
                    edges=edge_objs,
                    entry_point=entry_node,
                    crown_jewel=crown_node,
                    exploitability=exploitability,
                    impact=impact,
                    composite_score=composite,
                    title=title,
                    description=description,
                    mitre_atlas=mitre,
                ))

        # Deduplicate (same entry+crown, keep highest score)
        seen: dict[tuple, GraphPath] = {}
        for p in paths:
            key = (p.entry_point.id, p.crown_jewel.id)
            if key not in seen or p.composite_score > seen[key].composite_score:
                seen[key] = p

        return sorted(seen.values(), key=lambda p: -p.composite_score)

    # -- Blast radius --------------------------------------------------------

    def blast_radius(self, entry_id: str) -> dict[str, Any]:
        """
        From a given entry point, compute the total blast radius:
        which crown jewels are reachable and what is the aggregate impact?
        """
        reachable = self.reachable_from(entry_id)
        jewels = [
            self.nodes[nid] for nid in reachable
            if nid in self.nodes and (self.nodes[nid].is_crown_jewel or self.nodes[nid].crown_jewel_value > 50)
        ]
        total_value = sum(j.crown_jewel_value for j in jewels)
        return {
            "entry_point": entry_id,
            "reachable_nodes": len(reachable),
            "crown_jewels_reachable": [j.label for j in jewels],
            "aggregate_impact": min(total_value, 100),
            "max_single_impact": max((j.crown_jewel_value for j in jewels), default=0),
        }

    # -- Trust score ---------------------------------------------------------

    def trust_score(self, node_id: str) -> dict[str, Any]:
        """
        Compute a trust score (0-100) for a node, especially MCP servers.
        Higher = more trustworthy.
        Deductions for: dangerous capabilities, no auth, reachable from attacker inputs,
        many outbound edges, connection to crown jewels.
        """
        node = self.nodes.get(node_id)
        if not node:
            return {"score": 0, "reasons": ["Node not found"]}

        score = 100
        reasons: list[str] = []

        # Deduct for dangerous outbound edges
        out_edges = self._adj.get(node_id, [])
        dangerous_edge_types = {EdgeType.EXECUTES, EdgeType.EXFILTRATES, EdgeType.ESCALATES}
        for edge in out_edges:
            if edge.type in dangerous_edge_types:
                score -= 25
                reasons.append(f"Has {edge.type.value} edge to {self.nodes.get(edge.dst, Node(id=edge.dst, type=NodeType.RESOURCE, label=edge.dst)).label}")
            elif edge.type == EdgeType.WRITES:
                score -= 10
                reasons.append(f"Can write to {self.nodes.get(edge.dst, Node(id=edge.dst, type=NodeType.RESOURCE, label=edge.dst)).label}")

        # Deduct if reachable from attacker entry points
        for entry_id, entry_node in ATTACKER_ENTRY_NODES.items():
            if entry_node.attacker_controlled and entry_id in self.nodes:
                reachable = self.reachable_from(entry_id)
                if node_id in reachable:
                    score -= 15
                    reasons.append(f"Reachable from attacker-controlled '{entry_node.label}'")
                    break

        # Deduct for no authentication (if MCP server)
        if node.type == NodeType.MCP_SERVER:
            if not node.properties.get("has_auth"):
                score -= 20
                reasons.append("No authentication configured")
            if node.properties.get("allows_wildcard_permissions"):
                score -= 15
                reasons.append("Wildcard permissions declared")

        # Deduct for crown jewel adjacency
        for edge in out_edges:
            dst = self.nodes.get(edge.dst)
            if dst and dst.is_crown_jewel:
                score -= 20
                reasons.append(f"Direct access to crown jewel: {dst.label}")

        score = max(0, score)
        level = "HIGH" if score >= 70 else "MEDIUM" if score >= 40 else "LOW"
        return {
            "node_id": node_id,
            "node_label": node.label,
            "trust_score": score,
            "trust_level": level,
            "deductions": reasons,
        }

    # -- Serialisation --------------------------------------------------------

    def prune_disconnected_nodes(self) -> None:
        """Remove nodes that are not reachable from an attacker-controlled entry point or a crown jewel."""
        reachable_ids = set()
        for entry_id in [nid for nid, n in self.nodes.items() if n.attacker_controlled]:
            reachable_ids.update(self.reachable_from(entry_id))

        removed_ids = set()
        for node_id in list(self.nodes):
            if node_id in reachable_ids:
                continue
            if node_id in ATTACKER_ENTRY_NODES or node_id in CROWN_JEWEL_NODES:
                continue
            self.nodes.pop(node_id, None)
            removed_ids.add(node_id)

        self.edges = [e for e in self.edges if e.src not in removed_ids and e.dst not in removed_ids]
        self._adj = defaultdict(list)
        self._radj = defaultdict(list)
        for edge in self.edges:
            self._adj[edge.src].append(edge)
            self._radj[edge.dst].append(edge)

    def to_dict(self) -> dict:
        return {
            "nodes": [
                {
                    "id": n.id, "type": n.type.value, "label": n.label,
                    "attacker_controlled": n.attacker_controlled,
                    "is_crown_jewel": n.is_crown_jewel,
                    "crown_jewel_value": n.crown_jewel_value,
                    "trust_boundary": n.trust_boundary,
                    "properties": n.properties,
                }
                for n in self.nodes.values()
            ],
            "edges": [
                {
                    "src": e.src, "dst": e.dst, "type": e.type.value,
                    "label": e.label, "confidence": e.confidence, "mitre": e.mitre,
                }
                for e in self.edges
            ],
        }


# -- Scoring helpers ----------------------------------------------------------

def _score_exploitability(nodes: list[Node], edges: list[Edge]) -> float:
    """
    0.0 - 1.0: how easy is this path to exploit?
    Shorter paths with attacker-controlled entries and high-confidence edges = higher score.
    """
    if not nodes:
        return 0.0
    # Path length penalty (longer paths are harder to exploit)
    length_factor = max(0.3, 1.0 - (len(nodes) - 2) * 0.1)
    # Confidence factor (average edge confidence)
    avg_conf = sum(e.confidence for e in edges) / len(edges) if edges else 1.0
    # Entry point factor
    entry_factor = 1.0 if nodes[0].attacker_controlled else 0.6
    return round(length_factor * avg_conf * entry_factor, 3)


def _build_narrative(entry: Node, crown: Node, nodes: list[Node], edges: list[Edge]) -> tuple[str, str]:
    """Generate a human-readable title and description for an attack path."""
    step_labels = [n.label for n in nodes]
    chain = " -> ".join(step_labels)

    title = f"{entry.label} -> {crown.label}"

    edge_verbs = {
        EdgeType.EXECUTES: "executes",
        EdgeType.READS: "reads from",
        EdgeType.WRITES: "writes to",
        EdgeType.CALLS: "calls",
        EdgeType.EXFILTRATES: "exfiltrates data to",
        EdgeType.ESCALATES: "escalates privileges via",
        EdgeType.INJECTS: "injects malicious instructions into",
        EdgeType.DEPENDS_ON: "depends on",
        EdgeType.TRUSTS: "trusts",
    }

    steps = []
    for i, edge in enumerate(edges):
        src_label = nodes[i].label if i < len(nodes) else "?"
        dst_label = nodes[i+1].label if i+1 < len(nodes) else "?"
        verb = edge_verbs.get(edge.type, "accesses")
        steps.append(f"{src_label} {verb} {dst_label}")

    description = (
        f"An attacker controlling '{entry.label}' can reach '{crown.label}' "
        f"(impact value: {crown.crown_jewel_value}/100) via the following chain:\n\n"
        f"  {chain}\n\n"
        "Step-by-step:\n" +
        "\n".join(f"  {i+1}. {s}" for i, s in enumerate(steps)) +
        f"\n\nImpact: {crown.properties.get('impact', 'High-value asset compromised')}"
    )

    return title, description


# -- Graph builder from scan results -----------------------------------------

def build_graph_from_scan(result: ScanResult) -> AttackGraph:
    """
    Construct an AttackGraph from a ScanResult.
    Works with agent_scanner, mcp_scanner, and supply_chain_scanner results.
    """
    g = AttackGraph()
    caps = result.metadata.get("capabilities_detected", [])
    cap_to_tools = result.metadata.get("cap_to_tools", {})
    scanner = result.scanner_type

    # Add the agent/server as a node
    agent_node = Node(
        id="agent",
        type=NodeType.AGENT if scanner in {"agent_scanner", "source_scanner"} else NodeType.MCP_SERVER,
        label=result.metadata.get("agent_name", result.target.split("/")[-1]),
        trust_boundary=True,
        properties={
            "target": result.target,
            "tool_count": result.metadata.get("tool_count", 0),
            "has_auth": result.metadata.get("has_auth", False),
        }
    )
    g.add_node(agent_node)

    # Agent trusts user prompt -> add injection edge
    g.add_edge(Edge(
        src="user_prompt", dst="agent",
        type=EdgeType.INJECTS,
        label="prompt injection",
        confidence=0.9,
        mitre=["AML.T0051"],
    ))

    # Map capabilities to graph edges
    if "code_execution" in caps:
        g.add_node(Node(
            id="code_runtime",
            type=NodeType.PROCESS,
            label="Code Interpreter / Eval Runtime",
            properties={"impact": "Arbitrary code execution and eval-based runtime abuse"},
        ))

    cap_edge_map: dict[str, list[tuple]] = {
        "shell_exec": [
            ("agent", "shell_process", EdgeType.EXECUTES, 1.0, ["AML.T0017"]),
        ],
        "code_execution": [
            ("agent", "code_runtime", EdgeType.EXECUTES, 1.0, ["AML.T0017"]),
        ],
        "secret_access": [
            ("agent", "aws_credentials", EdgeType.READS, 1.0, ["AML.T0051"]),
            ("agent", "api_keys", EdgeType.READS, 0.9, ["AML.T0051"]),
        ],
        "network_egress": [
            ("agent", "external_network", EdgeType.EXFILTRATES, 0.85, ["AML.T0040"]),
        ],
        "database": [
            ("agent", "database_contents", EdgeType.READS, 1.0, ["AML.T0051"]),
            ("agent", "pii_store", EdgeType.READS, 0.8, ["AML.T0051"]),
        ],
        "file_write": [
            ("agent", "filesystem", EdgeType.WRITES, 1.0, ["AML.T0048"]),
        ],
        "file_read": [
            ("agent", "filesystem", EdgeType.READS, 1.0, ["AML.T0051"]),
        ],
        "cloud_api": [
            ("agent", "aws_credentials", EdgeType.ESCALATES, 0.8, ["AML.T0048"]),
        ],
    }

    for cap in caps:
        if cap in cap_edge_map:
            for src, dst, etype, conf, mitre in cap_edge_map[cap]:
                # Add tool node if we know which tool
                tools_for_cap = cap_to_tools.get(cap, [])
                if tools_for_cap:
                    tool_id = f"tool_{cap}"
                    tool_node = Node(
                        id=tool_id,
                        type=NodeType.TOOL,
                        label=tools_for_cap[0],
                        properties={"capability": cap, "all_tools": tools_for_cap},
                    )
                    g.add_node(tool_node)
                    # agent calls tool
                    g.add_edge(Edge(
                        src="agent", dst=tool_id,
                        type=EdgeType.CALLS,
                        label=f"invokes {tools_for_cap[0]}",
                        confidence=1.0,
                    ))
                    # tool accesses resource
                    g.add_edge(Edge(
                        src=tool_id, dst=dst,
                        type=etype,
                        label=f"{etype.value} via {tools_for_cap[0]}",
                        confidence=conf,
                        mitre=mitre,
                    ))
                else:
                    # Direct edge agent -> resource
                    g.add_edge(Edge(
                        src=src, dst=dst,
                        type=etype,
                        label=f"{cap} capability",
                        confidence=conf,
                        mitre=mitre,
                    ))

    # Shell -> credentials escalation path (if both exist)
    if "shell_exec" in caps and "secret_access" in caps:
        g.add_edge(Edge(
            src="shell_process", dst="aws_credentials",
            type=EdgeType.READS,
            label="read env vars / credential files",
            confidence=0.9,
            mitre=["AML.T0051"],
        ))

    # Credentials -> external (if network exists)
    if "secret_access" in caps and "network_egress" in caps:
        g.add_edge(Edge(
            src="aws_credentials", dst="external_network",
            type=EdgeType.EXFILTRATES,
            label="POST to attacker server",
            confidence=0.85,
            mitre=["AML.T0040"],
        ))
        g.add_edge(Edge(
            src="api_keys", dst="external_network",
            type=EdgeType.EXFILTRATES,
            label="POST to attacker server",
            confidence=0.85,
            mitre=["AML.T0040"],
        ))

    # Database -> external (if network exists)
    if "database" in caps and "network_egress" in caps:
        g.add_edge(Edge(
            src="database_contents", dst="external_network",
            type=EdgeType.EXFILTRATES,
            label="exfiltrate query results",
            confidence=0.8,
            mitre=["AML.T0040"],
        ))

    # Shell -> filesystem
    if "shell_exec" in caps:
        g.add_edge(Edge(
            src="shell_process", dst="filesystem",
            type=EdgeType.WRITES,
            label="write malicious files",
            confidence=0.95,
            mitre=["AML.T0048"],
        ))

    g.prune_disconnected_nodes()
    return g


def graph_paths_to_attack_paths(paths: list[GraphPath]) -> list[AttackPath]:
    """Convert GraphPath objects to AgentScan AttackPath objects for unified output."""
    result = []
    for gp in paths:
        severity = (
            Severity.CRITICAL if gp.composite_score >= 60 else
            Severity.HIGH if gp.composite_score >= 35 else
            Severity.MEDIUM
        )

        finding = Finding(
            id=f"GRAPH-{gp.entry_point.id[:8].upper()}-{gp.crown_jewel.id[:8].upper()}",
            title=gp.title,
            severity=severity,
            confidence=ConfidenceLevel.HIGH if gp.exploitability >= 0.7 else ConfidenceLevel.MEDIUM,
            scanner="attack_graph",
            explanation=gp.description,
            impact=gp.crown_jewel.properties.get("impact", "High-value asset compromised"),
            remediation="Break the attack chain by removing or scoping the tools that form the intermediate steps.",
            evidence=[Evidence(
                source="attack_graph",
                field="path",
                observed_value=" -> ".join(gp.step_labels()),
                explanation=f"Exploitability: {gp.exploitability:.0%}  Impact: {gp.impact}/100  Score: {gp.composite_score:.1f}",
            )],
            mitre_atlas=gp.mitre_atlas,
        )

        result.append(AttackPath(
            id=f"GRAPH-PATH-{gp.entry_point.id.upper()}-{gp.crown_jewel.id.upper()}",
            title=gp.title,
            severity=severity,
            steps=[finding],
            entry_point=gp.entry_point.label,
            impact=gp.crown_jewel.properties.get("impact", "High-value asset compromised"),
            description=gp.description,
            mitre_atlas=gp.mitre_atlas,
        ))
    return result
