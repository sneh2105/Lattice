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

    NOTE: this does NOT pre-populate every possible entry-point/crown-jewel
    node. A node only exists if it is actually used by an edge -- rendering
    a disconnected node (e.g. "AWS / Cloud" or "Tool Response" with zero
    edges because no finding actually reached them) misrepresents the scan
    as finding more than it did. Use add_predefined_entry_node /
    add_predefined_crown_jewel to opt a specific known node in explicitly.
    """

    def __init__(self, prepopulate: bool = True):
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []
        self._adj: dict[str, list[Edge]] = defaultdict(list)   # adjacency list
        self._radj: dict[str, list[Edge]] = defaultdict(list)  # reverse adjacency

        # Other subsystems (trust_flow, mcp_trust_chain, ai_sql query engine,
        # mcp_scanner_v2) build an AttackGraph and reference well-known node
        # ids like "user_prompt" / "aws_credentials" directly without adding
        # them first, so this default stays on for those callers.
        # build_graph_from_scan() below opts OUT (prepopulate=False) because
        # it adds only the nodes an actual attack path touches, then prunes
        # anything left with zero edges -- see the "no orphan nodes" fix.
        if prepopulate:
            for node in ATTACKER_ENTRY_NODES.values():
                self.add_node(node)
            for node in CROWN_JEWEL_NODES.values():
                self.add_node(node)

    def add_predefined_entry_node(self, node_id: str) -> None:
        """Opt-in helper: add one of the known ATTACKER_ENTRY_NODES by id."""
        if node_id in ATTACKER_ENTRY_NODES and node_id not in self.nodes:
            self.add_node(ATTACKER_ENTRY_NODES[node_id])

    def add_predefined_crown_jewel(self, node_id: str) -> None:
        """Opt-in helper: add one of the known CROWN_JEWEL_NODES by id."""
        if node_id in CROWN_JEWEL_NODES and node_id not in self.nodes:
            self.add_node(CROWN_JEWEL_NODES[node_id])

    def prune_disconnected_nodes(self) -> None:
        """Remove any node with zero edges (no in-edge and no out-edge).
        Used by build_graph_from_scan so a rendered graph never shows a
        floating node that no actual finding/attack path reached."""
        connected = set()
        for e in self.edges:
            connected.add(e.src)
            connected.add(e.dst)
        for nid in list(self.nodes.keys()):
            if nid not in connected:
                del self.nodes[nid]

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

# Maps a Finding's tags to a graph node type + label + edge type.
# CRITICAL DISTINCTION (per issue): a finding tagged "code_execution" with
# "behavioral-detection" (the eval()/exec() AST-body detector) is a DIFFERENT
# exploitation mechanism than "shell_exec" (subprocess/os.system) -- arbitrary
# Python code execution vs OS command execution. They must render as
# different node types/labels because the responder's remediation differs
# (sandboxing an eval() call vs restricting subprocess calls).
_TAG_TO_NODE_SPEC = {
    "code_execution": {
        "node_id": "code_exec_runtime",
        "node_type": NodeType.PROCESS,
        "label": "Code Execution (Arbitrary Python)",
        "impact": "Arbitrary Python code execution via eval()/exec() -- full runtime compromise",
        "crown_jewel_value": 95,
        "edge_type": EdgeType.EXECUTES,
        "mitre": ["AML.T0017"],
    },
    "shell_exec": {
        "node_id": "shell_process",
        "node_type": NodeType.PROCESS,
        "label": "OS Shell / Command Execution",
        "impact": "Arbitrary OS command execution, persistence, lateral movement",
        "crown_jewel_value": 95,
        "edge_type": EdgeType.EXECUTES,
        "mitre": ["AML.T0017"],
    },
    "secret_access": {
        "node_id": "aws_credentials",
        "node_type": NodeType.CROWN_JEWEL,
        "label": "AWS / Cloud Credentials",
        "impact": "Full cloud account takeover",
        "crown_jewel_value": 100,
        "edge_type": EdgeType.READS,
        "mitre": ["AML.T0051"],
    },
    "cloud_api": {
        "node_id": "aws_credentials",
        "node_type": NodeType.CROWN_JEWEL,
        "label": "AWS / Cloud Credentials",
        "impact": "Full cloud account takeover",
        "crown_jewel_value": 100,
        "edge_type": EdgeType.ESCALATES,
        "mitre": ["AML.T0048"],
    },
    "network_egress": {
        "node_id": "external_network",
        "node_type": NodeType.NETWORK,
        "label": "External Network / Internet",
        "impact": "Data exfiltration, C2 communication",
        "crown_jewel_value": 60,
        "edge_type": EdgeType.EXFILTRATES,
        "mitre": ["AML.T0040"],
    },
    "database": {
        "node_id": "database_contents",
        "node_type": NodeType.CROWN_JEWEL,
        "label": "Database Contents (PII / Financial)",
        "impact": "Mass data exfiltration",
        "crown_jewel_value": 85,
        "edge_type": EdgeType.READS,
        "mitre": ["AML.T0051"],
    },
    "file_write": {
        "node_id": "filesystem",
        "node_type": NodeType.RESOURCE,
        "label": "Host Filesystem",
        "impact": "Persistence, tampering, data destruction",
        "crown_jewel_value": 50,
        "edge_type": EdgeType.WRITES,
        "mitre": ["AML.T0048"],
    },
    "file_read": {
        "node_id": "filesystem",
        "node_type": NodeType.RESOURCE,
        "label": "Host Filesystem",
        "impact": "Sensitive file disclosure",
        "crown_jewel_value": 50,
        "edge_type": EdgeType.READS,
        "mitre": ["AML.T0051"],
    },
    "email_send": {
        "node_id": "email_system",
        "node_type": NodeType.NETWORK,
        "label": "Email / Messaging System",
        "impact": "Phishing, spam, social engineering at scale",
        "crown_jewel_value": 55,
        "edge_type": EdgeType.EXFILTRATES,
        "mitre": ["AML.T0040"],
    },
    "financial_transaction": {
        "node_id": "financial_system",
        "node_type": NodeType.CROWN_JEWEL,
        "label": "Financial / Payment System",
        "impact": "Fraudulent transactions, financial loss",
        "crown_jewel_value": 100,
        "edge_type": EdgeType.EXECUTES,
        "mitre": ["AML.T0048"],
    },
}


def _finding_tool_name(finding) -> str:
    """Extract the tool name from a Finding's title, e.g. "Tool 'foo' grants..." -> "foo"."""
    title = getattr(finding, "title", "") or ""
    if "\'" in title:
        parts = title.split("\'")
        if len(parts) >= 2:
            return parts[1]
    return title[:30]


def _node_spec_for_finding(finding):
    """
    Pick the graph node spec for a Finding, checking tags in a priority order
    so the MOST SPECIFIC mechanism wins when a finding has multiple tags.
    code_execution (eval/exec) is checked before shell_exec so a behavioral
    eval() detection never gets mislabeled as generic shell access.

    Recognizes BOTH the standard capability tag vocabulary (agent_scanner/
    source_scanner: "shell_exec", "database", ...) AND the raw MCP scanner
    tag vocabulary ("MCP-SHELL", "MCP-DATABASE", ...) -- an MCP-derived
    AttackPath's steps carry the finding objects exactly as mcp_scanner
    produced them, with the MCP-native tags still attached, not translated.
    Without this alias map, MCP-derived attack paths render with zero
    mappable steps and vanish from the graph even though they're present in
    result.attack_paths (the same list PDF/compliance/SARIF report from).
    """
    tags = set(getattr(finding, "tags", []) or [])
    # Alias raw MCP tags onto the standard capability vocabulary
    mcp_aliases = {
        "MCP-SHELL": "shell_exec",
        "MCP-SECRETS": "secret_access",
        "MCP-NET": "network_egress",
        "MCP-DATABASE": "database",
        "MCP-CODE-EXEC": "code_execution",
    }
    for mcp_tag, std_tag in mcp_aliases.items():
        if mcp_tag in tags:
            tags.add(std_tag)

    priority = ["code_execution", "shell_exec", "financial_transaction",
                "secret_access", "database", "cloud_api", "network_egress",
                "file_write", "file_read", "email_send"]
    for tag in priority:
        if tag in tags and tag in _TAG_TO_NODE_SPEC:
            return tag, _TAG_TO_NODE_SPEC[tag]
    return None, None


def build_graph_from_scan(result: ScanResult) -> AttackGraph:
    """
    Build the attack graph DIRECTLY from result.attack_paths -- the exact
    same list the PDF, compliance report, and JSON/SARIF output use. This is
    the single-source-of-truth fix: the graph must never independently
    re-derive its own path list from a separate capabilities_detected
    reconstruction, because that guarantees the two will eventually diverge
    (which is exactly the bug this replaces).

    Every node added here comes from an actual step in an actual attack
    path -- there are no pre-populated placeholder nodes, so a node can never
    appear disconnected with zero edges.
    """
    # prepopulate=False: only add nodes an actual attack path touches, then
    # prune any left with zero edges (fixes the "AWS/Cloud" and "Tool
    # Response" disconnected/orphaned node bug -- those were always-added
    # placeholder nodes from ATTACKER_ENTRY_NODES/CROWN_JEWEL_NODES that had
    # no edges unless a matching capability happened to fire).
    g = AttackGraph(prepopulate=False)

    agent_label = result.metadata.get("agent_name", result.target.split("/")[-1]) if result.metadata else result.target.split("/")[-1]
    agent_node = Node(
        id="agent",
        type=NodeType.AGENT if result.scanner_type in {"agent_scanner", "source_scanner", "merged"} else NodeType.MCP_SERVER,
        label=agent_label,
        trust_boundary=True,
        properties={"target": result.target},
    )

    for path in (result.attack_paths or []):
        entry_id = "user_prompt"
        g.add_predefined_entry_node(entry_id)
        g.add_node(agent_node)
        g.add_edge(Edge(
            src=entry_id, dst="agent", type=EdgeType.INJECTS,
            label="prompt injection", confidence=0.9, mitre=["AML.T0051"],
        ))

        prev_id = "agent"
        last_target_id = None
        last_target_node = None

        for step in (path.steps or []):
            tag, spec = _node_spec_for_finding(step)
            if not spec:
                continue  # skip steps we can't map to a concrete mechanism

            tool_name = _finding_tool_name(step)
            tool_id = "tool_" + "".join(c if c.isalnum() else "_" for c in tool_name.lower())

            tool_node = Node(
                id=tool_id, type=NodeType.TOOL, label=tool_name,
                properties={"capability": tag, "finding_id": step.id},
            )
            g.add_node(tool_node)
            g.add_edge(Edge(
                src=prev_id, dst=tool_id, type=EdgeType.CALLS,
                label="invokes " + tool_name, confidence=1.0,
            ))

            target_node = Node(
                id=spec["node_id"], type=spec["node_type"], label=spec["label"],
                is_crown_jewel=(spec["node_type"] == NodeType.CROWN_JEWEL or spec["crown_jewel_value"] > 50),
                crown_jewel_value=spec["crown_jewel_value"],
                properties={"impact": spec["impact"]},
            )
            g.add_node(target_node)
            g.add_edge(Edge(
                src=tool_id, dst=spec["node_id"], type=spec["edge_type"],
                label=spec["edge_type"].value + " via " + tool_name,
                confidence=0.9, mitre=spec["mitre"],
            ))

            prev_id = tool_id
            last_target_id = spec["node_id"]
            last_target_node = target_node

    g.prune_disconnected_nodes()
    return g



def graph_paths_from_attack_paths(result: ScanResult, g: AttackGraph) -> list[GraphPath]:
    """
    Convert result.attack_paths DIRECTLY into GraphPath objects, one for one.

    This is the actual single-source-of-truth fix: g.find_attack_paths() does
    its own independent BFS reconstruction over the graph\'s nodes/edges and
    dedupes multiple paths that happen to share the same (entry, crown_jewel)
    pair -- which under-counts relative to result.attack_paths whenever two
    distinct attack chains reach the same crown jewel by different
    mechanisms (e.g. "Credential exfiltration" via network_egress and "Cloud
    privilege escalation" via cloud_api both ending at aws_credentials).

    The PDF/compliance/JSON/SARIF outputs all report len(result.attack_paths)
    directly. For the graph to show the same count and the same named paths,
    it must consume that same list rather than re-deriving its own -- so this
    function is what agentscan.ui_server._get_graph() and cli_graph\'s
    terminal renderer should call instead of g.find_attack_paths().
    """
    graph_paths: list[GraphPath] = []

    for path in (result.attack_paths or []):
        node_objs: list[Node] = []
        edge_objs: list[Edge] = []

        entry_node = g.nodes.get("user_prompt")
        if entry_node is None:
            entry_node = ATTACKER_ENTRY_NODES["user_prompt"]
        node_objs.append(entry_node)

        agent_node = g.nodes.get("agent")
        if agent_node is not None:
            node_objs.append(agent_node)
            edge_objs.append(Edge(src="user_prompt", dst="agent", type=EdgeType.INJECTS,
                                  label="prompt injection", confidence=0.9, mitre=["AML.T0051"]))

        prev_id = "agent"
        crown_node = None

        for step in (path.steps or []):
            tag, spec = _node_spec_for_finding(step)
            if not spec:
                continue
            tool_name = _finding_tool_name(step)
            tool_id = "tool_" + "".join(c if c.isalnum() else "_" for c in tool_name.lower())
            tool_node = g.nodes.get(tool_id)
            if tool_node is None:
                continue
            node_objs.append(tool_node)
            edge_objs.append(Edge(src=prev_id, dst=tool_id, type=EdgeType.CALLS,
                                  label="invokes " + tool_name, confidence=1.0))

            target_node = g.nodes.get(spec["node_id"])
            if target_node is not None:
                node_objs.append(target_node)
                edge_objs.append(Edge(src=tool_id, dst=spec["node_id"], type=spec["edge_type"],
                                      label=spec["edge_type"].value + " via " + tool_name,
                                      confidence=0.9, mitre=spec["mitre"]))
                crown_node = target_node

            prev_id = tool_id

        if crown_node is None:
            # Path had no mappable steps -- skip rather than emit a broken GraphPath
            continue

        exploitability = _score_exploitability(node_objs, edge_objs)
        impact = crown_node.crown_jewel_value or 50

        graph_paths.append(GraphPath(
            nodes=node_objs,
            edges=edge_objs,
            entry_point=entry_node,
            crown_jewel=crown_node,
            exploitability=exploitability,
            impact=impact,
            composite_score=exploitability * impact,
            title=path.title,
            description=path.description,
            mitre_atlas=list(path.mitre_atlas or []),
        ))

    return graph_paths


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
