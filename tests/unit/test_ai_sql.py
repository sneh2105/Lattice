# -*- coding: utf-8 -*-
"""Tests for AI Security Query Language (AI-SQL)."""
import pytest
from agentscan.models import ScanResult
from agentscan.graph.engine import build_graph_from_scan
from agentscan.graph.ai_sql import AISQLEngine


def make_engine():
    result = ScanResult(
        target="test.yaml", scanner_type="agent_scanner",
        metadata={
            "capabilities_detected": ["shell_exec", "secret_access", "network_egress"],
            "cap_to_tools": {"shell_exec": ["bash"], "secret_access": ["vault"], "network_egress": ["http"]},
            "tool_count": 3,
        },
    )
    graph = build_graph_from_scan(result)
    return AISQLEngine(graph)


def test_find_crown_jewel():
    engine = make_engine()
    result = engine.query("FIND crown_jewel WHERE reachable_from = 'user_prompt'")
    assert result.success
    assert len(result.rows) > 0


def test_can_access_query():
    engine = make_engine()
    result = engine.query("CAN user_prompt ACCESS aws_credentials")
    assert result.success
    assert result.rows[0]["can_access"] is True


def test_path_from_to():
    engine = make_engine()
    result = engine.query("PATH FROM user_prompt TO shell_process")
    assert result.success
    assert len(result.rows) > 0


def test_blast_radius_query():
    engine = make_engine()
    result = engine.query("BLAST RADIUS OF user_prompt")
    assert result.success
    assert result.rows[0]["aggregate_impact"] > 0


def test_reachable_from_query():
    engine = make_engine()
    result = engine.query("REACHABLE FROM user_prompt")
    assert result.success
    assert len(result.rows) > 0


def test_count_query():
    engine = make_engine()
    result = engine.query("COUNT tool")
    assert result.success
    assert result.rows[0]["count"] >= 0


def test_trust_of_query():
    engine = make_engine()
    result = engine.query("TRUST OF agent")
    assert result.success
    assert "trust_score" in result.rows[0]


def test_unknown_node_returns_error():
    engine = make_engine()
    result = engine.query("PATH FROM nonexistent_node TO also_nonexistent")
    assert not result.success
    assert result.error


def test_unrecognised_query_type():
    engine = make_engine()
    result = engine.query("DELETE everything")
    assert not result.success
