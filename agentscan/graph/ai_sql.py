# -*- coding: utf-8 -*-
"""
AI Security Query Language (AI-SQL)
======================================
A small, purpose-built query language for asking security questions
over the attack graph, instead of manually reading reports.

Grammar (deliberately small and predictable, not full SQL):

  FIND <node_type> WHERE <condition> [AND <condition>]*
  PATH FROM <node> TO <node>
  REACHABLE FROM <node>
  CAN <node> ACCESS <node>
  BLAST RADIUS OF <node>
  TRUST OF <node>
  COUNT <node_type> WHERE <condition>

Examples:
  FIND tool WHERE capability = 'shell_exec'
  FIND crown_jewel WHERE reachable_from = 'user_prompt'
  PATH FROM user_prompt TO aws_credentials
  CAN agent ACCESS aws_credentials
  BLAST RADIUS OF user_prompt
  TRUST OF mcp_server_1
  COUNT tool WHERE severity = 'CRITICAL'

This is intentionally a small DSL, not a full query language — the value
is in making the graph queryable in security-analyst language, not in
language completeness.
"""

from __future__ import annotations
import re
import shlex
from dataclasses import dataclass, field
from typing import Any

from agentscan.graph.engine import AttackGraph
from agentscan.graph.nodes import Node, NodeType


@dataclass
class QueryResult:
    """Result of an AI-SQL query."""
    query: str
    query_type: str
    success: bool
    rows: list[dict[str, Any]]
    error: str | None = None
    explanation: str = ""


class AISQLError(Exception):
    pass


class AISQLEngine:
    """
    Parses and executes AI-SQL queries against an AttackGraph.

    Usage:
        engine = AISQLEngine(graph)
        result = engine.query("FIND tool WHERE capability = 'shell_exec'")
        for row in result.rows:
            print(row)
    """

    def __init__(self, graph: AttackGraph):
        self.graph = graph

    def query(self, query_str: str) -> QueryResult:
        query_str = query_str.strip()
        try:
            upper = query_str.upper()
            if upper.startswith("FIND"):
                return self._exec_find(query_str)
            elif upper.startswith("PATH FROM"):
                return self._exec_path(query_str)
            elif upper.startswith("REACHABLE FROM"):
                return self._exec_reachable(query_str)
            elif upper.startswith("CAN "):
                return self._exec_can_access(query_str)
            elif upper.startswith("BLAST RADIUS OF"):
                return self._exec_blast_radius(query_str)
            elif upper.startswith("TRUST OF"):
                return self._exec_trust(query_str)
            elif upper.startswith("COUNT"):
                return self._exec_count(query_str)
            else:
                return QueryResult(
                    query=query_str, query_type="unknown", success=False, rows=[],
                    error=f"Unrecognised query type. Supported: FIND, PATH FROM...TO, "
                          f"REACHABLE FROM, CAN...ACCESS, BLAST RADIUS OF, TRUST OF, COUNT",
                )
        except AISQLError as e:
            return QueryResult(query=query_str, query_type="error", success=False, rows=[], error=str(e))
        except Exception as e:
            return QueryResult(query=query_str, query_type="error", success=False, rows=[],
                              error=f"Query execution error: {e}")

    # ── FIND ──────────────────────────────────────────────────────────────────

    def _exec_find(self, q: str) -> QueryResult:
        # FIND <node_type> [WHERE <conditions>]
        m = re.match(r"FIND\s+(\w+)\s*(?:WHERE\s+(.*))?$", q, re.IGNORECASE)
        if not m:
            raise AISQLError("Syntax: FIND <node_type> [WHERE condition1 AND condition2...]")

        node_type_str = m.group(1).lower()
        where_clause = m.group(2)

        nodes = self._filter_by_type(node_type_str)

        if where_clause:
            conditions = self._parse_conditions(where_clause)
            nodes = [n for n in nodes if self._matches_conditions(n, conditions)]

        rows = [self._node_to_row(n) for n in nodes]
        return QueryResult(
            query=q, query_type="find", success=True, rows=rows,
            explanation=f"Found {len(rows)} node(s) matching '{node_type_str}'"
                       + (f" WHERE {where_clause}" if where_clause else ""),
        )

    def _filter_by_type(self, type_str: str) -> list[Node]:
        # Map query keywords to NodeType, and handle synthetic types like "crown_jewel" via flags
        type_map = {
            "tool": NodeType.TOOL, "agent": NodeType.AGENT, "mcp_server": NodeType.MCP_SERVER,
            "resource": NodeType.RESOURCE, "network": NodeType.NETWORK, "process": NodeType.PROCESS,
            "entry_point": NodeType.ENTRY_POINT,
        }
        if type_str == "crown_jewel":
            return [n for n in self.graph.nodes.values() if n.is_crown_jewel]
        if type_str == "node" or type_str == "*":
            return list(self.graph.nodes.values())
        if type_str in type_map:
            return [n for n in self.graph.nodes.values() if n.type == type_map[type_str]]
        raise AISQLError(f"Unknown node type '{type_str}'. Supported: tool, agent, mcp_server, "
                         f"resource, network, process, entry_point, crown_jewel, node")

    def _parse_conditions(self, where: str) -> list[tuple[str, str, str]]:
        """Parse 'field = value AND field2 = value2' into [(field, op, value), ...]"""
        conditions = []
        parts = re.split(r"\s+AND\s+", where, flags=re.IGNORECASE)
        for part in parts:
            m = re.match(r"(\w+)\s*(=|!=|>=|<=|>|<)\s*'?([^']*)'?$", part.strip())
            if not m:
                raise AISQLError(f"Cannot parse condition: '{part}'")
            conditions.append((m.group(1).lower(), m.group(2), m.group(3).strip()))
        return conditions

    def _matches_conditions(self, node: Node, conditions: list[tuple[str, str, str]]) -> bool:
        for field, op, value in conditions:
            if field == "reachable_from":
                reachable = self.graph.reachable_from(value)
                is_reachable = node.id in reachable
                target_val = "true" if is_reachable else "false"
                if not self._compare(target_val, op, value.lower() if op == "=" else value):
                    # for reachable_from, compare boolean intent: WHERE reachable_from = 'X' means "is reachable from X"
                    pass
                if op == "=" and not is_reachable:
                    return False
                continue
            node_val = self._get_node_field(node, field)
            if node_val is None:
                return False
            if not self._compare(node_val, op, value):
                return False
        return True

    def _get_node_field(self, node: Node, field: str) -> Any:
        if field == "capability":
            return node.properties.get("capability", "")
        if field == "label":
            return node.label
        if field == "type":
            return node.type.value
        if field == "scoped":
            return str(node.scoped if hasattr(node, "scoped") else "").lower()
        if field == "attacker_controlled":
            return str(node.attacker_controlled).lower()
        if field == "is_crown_jewel":
            return str(node.is_crown_jewel).lower()
        if field == "crown_jewel_value":
            return node.crown_jewel_value
        if field == "reachable_from":
            # Special handled in _matches_conditions directly — placeholder
            return None
        if field == "severity":
            # Inferred from crown_jewel_value
            if node.crown_jewel_value >= 80: return "CRITICAL"
            if node.crown_jewel_value >= 50: return "HIGH"
            if node.crown_jewel_value >= 20: return "MEDIUM"
            return "LOW"
        return node.properties.get(field)

    def _compare(self, node_val: Any, op: str, value: str) -> bool:
        node_str = str(node_val).lower()
        value_str = value.lower()
        if op == "=":
            return node_str == value_str
        if op == "!=":
            return node_str != value_str
        try:
            nv, vv = float(node_val), float(value)
            if op == ">": return nv > vv
            if op == "<": return nv < vv
            if op == ">=": return nv >= vv
            if op == "<=": return nv <= vv
        except (ValueError, TypeError):
            pass
        return False

    # ── PATH FROM x TO y ──────────────────────────────────────────────────────

    def _exec_path(self, q: str) -> QueryResult:
        m = re.match(r"PATH\s+FROM\s+(\S+)\s+TO\s+(\S+)$", q, re.IGNORECASE)
        if not m:
            raise AISQLError("Syntax: PATH FROM <node_id> TO <node_id>")
        src, dst = m.group(1), m.group(2)

        if src not in self.graph.nodes:
            raise AISQLError(f"Unknown node '{src}'")
        if dst not in self.graph.nodes:
            raise AISQLError(f"Unknown node '{dst}'")

        path = self.graph.shortest_path(src, dst)
        if not path:
            return QueryResult(
                query=q, query_type="path", success=True, rows=[],
                explanation=f"No path exists from '{src}' to '{dst}'",
            )

        rows = [{"step": i, "node_id": nid, "label": self.graph.nodes[nid].label}
                for i, nid in enumerate(path)]
        return QueryResult(
            query=q, query_type="path", success=True, rows=rows,
            explanation=f"Path found: {len(path)} hops from '{src}' to '{dst}'",
        )

    # ── REACHABLE FROM ────────────────────────────────────────────────────────

    def _exec_reachable(self, q: str) -> QueryResult:
        m = re.match(r"REACHABLE\s+FROM\s+(\S+)$", q, re.IGNORECASE)
        if not m:
            raise AISQLError("Syntax: REACHABLE FROM <node_id>")
        src = m.group(1)
        if src not in self.graph.nodes:
            raise AISQLError(f"Unknown node '{src}'")

        reachable = self.graph.reachable_from(src)
        rows = [self._node_to_row(self.graph.nodes[nid]) for nid in reachable if nid != src]
        return QueryResult(
            query=q, query_type="reachable", success=True, rows=rows,
            explanation=f"{len(rows)} node(s) reachable from '{src}'",
        )

    # ── CAN x ACCESS y ────────────────────────────────────────────────────────

    def _exec_can_access(self, q: str) -> QueryResult:
        m = re.match(r"CAN\s+(\S+)\s+ACCESS\s+(\S+)$", q, re.IGNORECASE)
        if not m:
            raise AISQLError("Syntax: CAN <node_id> ACCESS <node_id>")
        src, dst = m.group(1), m.group(2)

        if src not in self.graph.nodes:
            raise AISQLError(f"Unknown node '{src}'")
        if dst not in self.graph.nodes:
            raise AISQLError(f"Unknown node '{dst}'")

        reachable = self.graph.reachable_from(src)
        can_access = dst in reachable
        path = self.graph.shortest_path(src, dst) if can_access else None

        return QueryResult(
            query=q, query_type="can_access", success=True,
            rows=[{"src": src, "dst": dst, "can_access": can_access,
                  "path": " → ".join(self.graph.nodes[n].label for n in path) if path else None}],
            explanation=f"{'YES' if can_access else 'NO'} — '{src}' can{'' if can_access else 'not'} reach '{dst}'",
        )

    # ── BLAST RADIUS OF ───────────────────────────────────────────────────────

    def _exec_blast_radius(self, q: str) -> QueryResult:
        m = re.match(r"BLAST\s+RADIUS\s+OF\s+(\S+)$", q, re.IGNORECASE)
        if not m:
            raise AISQLError("Syntax: BLAST RADIUS OF <node_id>")
        node_id = m.group(1)
        if node_id not in self.graph.nodes:
            raise AISQLError(f"Unknown node '{node_id}'")

        br = self.graph.blast_radius(node_id)
        return QueryResult(
            query=q, query_type="blast_radius", success=True,
            rows=[br],
            explanation=f"Blast radius from '{node_id}': {br['aggregate_impact']}/100 impact, "
                       f"{len(br['crown_jewels_reachable'])} crown jewels reachable",
        )

    # ── TRUST OF ──────────────────────────────────────────────────────────────

    def _exec_trust(self, q: str) -> QueryResult:
        m = re.match(r"TRUST\s+OF\s+(\S+)$", q, re.IGNORECASE)
        if not m:
            raise AISQLError("Syntax: TRUST OF <node_id>")
        node_id = m.group(1)
        if node_id not in self.graph.nodes:
            raise AISQLError(f"Unknown node '{node_id}'")

        trust = self.graph.trust_score(node_id)
        return QueryResult(
            query=q, query_type="trust", success=True, rows=[trust],
            explanation=f"Trust score of '{node_id}': {trust['trust_score']}/100 [{trust['trust_level']}]",
        )

    # ── COUNT ─────────────────────────────────────────────────────────────────

    def _exec_count(self, q: str) -> QueryResult:
        m = re.match(r"COUNT\s+(\w+)\s*(?:WHERE\s+(.*))?$", q, re.IGNORECASE)
        if not m:
            raise AISQLError("Syntax: COUNT <node_type> [WHERE condition]")
        node_type_str = m.group(1).lower()
        where_clause = m.group(2)

        nodes = self._filter_by_type(node_type_str)
        if where_clause:
            conditions = self._parse_conditions(where_clause)
            nodes = [n for n in nodes if self._matches_conditions(n, conditions)]

        return QueryResult(
            query=q, query_type="count", success=True,
            rows=[{"count": len(nodes)}],
            explanation=f"{len(nodes)} {node_type_str}(s) match the query",
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _node_to_row(self, node: Node) -> dict[str, Any]:
        return {
            "id": node.id, "label": node.label, "type": node.type.value,
            "is_crown_jewel": node.is_crown_jewel,
            "crown_jewel_value": node.crown_jewel_value,
            "attacker_controlled": node.attacker_controlled,
            "capability": node.properties.get("capability", ""),
        }


# ── Convenience: natural-language-ish query suggestions ──────────────────────

QUERY_EXAMPLES = [
    "FIND tool WHERE capability = 'shell_exec'",
    "FIND crown_jewel WHERE reachable_from = 'user_prompt'",
    "PATH FROM user_prompt TO aws_credentials",
    "REACHABLE FROM user_prompt",
    "CAN user_prompt ACCESS shell_process",
    "BLAST RADIUS OF user_prompt",
    "TRUST OF agent",
    "COUNT tool WHERE crown_jewel_value > 50",
]
