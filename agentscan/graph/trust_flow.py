# -*- coding: utf-8 -*-
"""
Trust Flow Graph
=================
Models how untrusted data crosses trust boundaries and reaches privileged actions.

Core insight: the attack graph engine shows WHAT is reachable.
The trust flow graph shows WHERE trust boundaries are crossed along the way --
which is the actual moment of compromise, not just the eventual impact.

A trust boundary crossing happens when:
  - Data originating from an UNTRUSTED source (user input, tool result, RAG doc)
  - Flows into a PRIVILEGED sink (shell exec, secret access, cloud API)
  - WITHOUT passing through a validation/sanitisation node

This is the AI-agent equivalent of taint tracking in traditional AppSec --
applied to data flow through LLM context rather than variable assignment.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum

from agentscan.graph.engine import AttackGraph
from agentscan.graph.nodes import Node, Edge, NodeType, EdgeType
from agentscan.models import Finding, Evidence, Severity, ConfidenceLevel


class TrustLevel(str, Enum):
    UNTRUSTED      = "untrusted"        # user input, tool results, RAG docs, external data
    SEMI_TRUSTED    = "semi_trusted"     # internal memory, prior agent outputs
    TRUSTED         = "trusted"          # system prompt, hardcoded config
    PRIVILEGED      = "privileged"       # crown jewels -- the sinks we care about


# Classify nodes by trust level based on type and properties
def _classify_trust(node: Node) -> TrustLevel:
    if node.attacker_controlled:
        return TrustLevel.UNTRUSTED
    if node.is_crown_jewel or node.crown_jewel_value >= 50:
        return TrustLevel.PRIVILEGED
    if node.type in (NodeType.TOOL, NodeType.RESOURCE):
        return TrustLevel.SEMI_TRUSTED
    if node.type in (NodeType.AGENT, NodeType.MCP_SERVER):
        return TrustLevel.TRUSTED
    return TrustLevel.SEMI_TRUSTED


@dataclass
class TrustBoundaryCrossing:
    """A single point where untrusted data flows toward a privileged sink."""
    edge: Edge
    src_node: Node
    dst_node: Node
    src_trust: TrustLevel
    dst_trust: TrustLevel
    is_sanitised: bool          # was there a validation step?
    severity: Severity
    description: str


@dataclass
class TrustFlowPath:
    """A complete path showing trust level transitions from source to sink."""
    nodes: list[Node]
    trust_levels: list[TrustLevel]
    crossings: list[TrustBoundaryCrossing]
    unsanitised_crossings: int
    title: str
    severity: Severity
    composite_score: float


@dataclass
class TrustFlowReport:
    """Complete trust flow analysis for an attack graph."""
    crossings: list[TrustBoundaryCrossing]
    paths: list[TrustFlowPath]
    findings: list[Finding]
    total_unsanitised_crossings: int
    riskiest_path: TrustFlowPath | None


# Known sanitisation node patterns (if these appear in the path, the crossing is "sanitised")
SANITISATION_MARKERS = {
    "guardrail", "validator", "sanitiser", "sanitizer", "filter",
    "content_filter", "output_filter", "moderation", "allowlist",
}


def _is_sanitised(graph: AttackGraph, src_id: str, dst_id: str) -> bool:
    """Check if any node between src and dst looks like a sanitisation step."""
    # Check node labels/properties for sanitisation markers
    for node_id in (src_id, dst_id):
        node = graph.get_node(node_id)
        if node:
            label_lower = node.label.lower()
            if any(marker in label_lower for marker in SANITISATION_MARKERS):
                return True
            if node.properties.get("sanitised") or node.properties.get("validated"):
                return True
    return False


def analyse_trust_flow(graph: AttackGraph) -> TrustFlowReport:
    """
    Walk every edge in the graph, classify trust levels on both ends,
    and flag every crossing from UNTRUSTED -> PRIVILEGED without sanitisation.
    """
    crossings: list[TrustBoundaryCrossing] = []

    for edge in graph.edges:
        src_node = graph.get_node(edge.src)
        dst_node = graph.get_node(edge.dst)
        if not src_node or not dst_node:
            continue

        src_trust = _classify_trust(src_node)
        dst_trust = _classify_trust(dst_node)

        # We care about: untrusted/semi-trusted flowing into privileged
        is_boundary_crossing = (
            src_trust in (TrustLevel.UNTRUSTED, TrustLevel.SEMI_TRUSTED)
            and dst_trust == TrustLevel.PRIVILEGED
        )
        # Also flag: untrusted flowing into trusted (e.g. tool result -> agent context)
        is_injection_crossing = (
            src_trust == TrustLevel.UNTRUSTED and dst_trust == TrustLevel.TRUSTED
        )

        if not (is_boundary_crossing or is_injection_crossing):
            continue

        sanitised = _is_sanitised(graph, edge.src, edge.dst)
        severity = Severity.CRITICAL if (is_boundary_crossing and not sanitised) else \
                   Severity.HIGH if not sanitised else Severity.LOW

        if is_boundary_crossing:
            desc = (
                f"Untrusted data from '{src_node.label}' flows directly into privileged "
                f"sink '{dst_node.label}' via a {edge.type.value} edge"
                f"{' (sanitised)' if sanitised else ' WITHOUT sanitisation'}."
            )
        else:
            desc = (
                f"Untrusted data from '{src_node.label}' flows into trusted context "
                f"'{dst_node.label}' -- this can poison the agent's decision-making "
                f"for all subsequent privileged actions."
            )

        crossings.append(TrustBoundaryCrossing(
            edge=edge, src_node=src_node, dst_node=dst_node,
            src_trust=src_trust, dst_trust=dst_trust,
            is_sanitised=sanitised, severity=severity, description=desc,
        ))

    # Build trust flow paths from attack paths (reuse existing path-finding)
    graph_paths = graph.find_attack_paths()
    flow_paths: list[TrustFlowPath] = []

    for gp in graph_paths:
        trust_levels = [_classify_trust(n) for n in gp.nodes]
        path_crossings = []
        for i in range(len(gp.nodes) - 1):
            matching = [c for c in crossings
                       if c.src_node.id == gp.nodes[i].id and c.dst_node.id == gp.nodes[i+1].id]
            path_crossings.extend(matching)

        unsanitised = sum(1 for c in path_crossings if not c.is_sanitised)

        flow_paths.append(TrustFlowPath(
            nodes=gp.nodes, trust_levels=trust_levels,
            crossings=path_crossings, unsanitised_crossings=unsanitised,
            title=gp.title,
            severity=Severity.CRITICAL if unsanitised >= 1 else Severity.MEDIUM,
            composite_score=gp.composite_score + (unsanitised * 10),
        ))

    flow_paths.sort(key=lambda p: -p.composite_score)
    riskiest = flow_paths[0] if flow_paths else None

    # Build findings
    findings: list[Finding] = []
    unsanitised_crossings = [c for c in crossings if not c.is_sanitised]

    for i, crossing in enumerate(unsanitised_crossings[:10]):
        findings.append(Finding(
            id=f"TRUST-CROSS-{i+1}-{crossing.src_node.id[:10].upper()}-{crossing.dst_node.id[:10].upper()}",
            title=f"Unsanitised trust boundary crossing: {crossing.src_node.label} -> {crossing.dst_node.label}",
            severity=crossing.severity,
            confidence=ConfidenceLevel.HIGH,
            scanner="trust_flow",
            explanation=crossing.description,
            impact=(
                f"Data from an untrusted source can directly influence "
                f"'{crossing.dst_node.label}' with no validation step in between. "
                "This is the structural precondition for prompt injection to succeed."
            ),
            remediation=(
                f"Insert a validation/sanitisation step between '{crossing.src_node.label}' "
                f"and '{crossing.dst_node.label}'. Treat all data from this source as untrusted "
                "until explicitly validated against an allowlist or schema."
            ),
            evidence=[Evidence(
                source="trust_flow_graph",
                field=f"edge[{crossing.src_node.id}->{crossing.dst_node.id}]",
                observed_value=f"{crossing.src_trust.value} -> {crossing.dst_trust.value}",
                explanation=f"Edge type: {crossing.edge.type.value}, confidence: {crossing.edge.confidence}",
            )],
            mitre_atlas=crossing.edge.mitre or ["AML.T0051"],
            tags=["trust-flow", "boundary-crossing"],
        ))

    return TrustFlowReport(
        crossings=crossings,
        paths=flow_paths,
        findings=findings,
        total_unsanitised_crossings=len(unsanitised_crossings),
        riskiest_path=riskiest,
    )
