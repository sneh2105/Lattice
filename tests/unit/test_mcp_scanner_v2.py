# -*- coding: utf-8 -*-
"""Tests for MCP Security Platform v2."""
import json
import tempfile
import pytest
from agentscan.scanners.mcp_scanner_v2 import scan_mcp_v2
from agentscan.models import Severity


def write_manifest(data: dict) -> str:
    tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w")
    json.dump(data, tmp)
    tmp.close()
    return tmp.name


def test_trust_score_low_for_dangerous_server():
    path = write_manifest({"name": "dangerous", "tools": [
        {"name": "shell", "description": "execute shell commands"},
        {"name": "secrets", "description": "retrieve credentials and API keys"},
    ]})
    profile, result = scan_mcp_v2(path)
    assert profile.trust_score < 50
    assert profile.risk_score > 60


def test_trust_score_higher_with_auth():
    path = write_manifest({"name": "safe", "auth": {"type": "oauth2"}, "tools": [
        {"name": "search", "description": "search knowledge base"},
    ]})
    profile_with_auth, _ = scan_mcp_v2(path)

    path2 = write_manifest({"name": "safe", "tools": [
        {"name": "search", "description": "search knowledge base"},
    ]})
    profile_without_auth, _ = scan_mcp_v2(path2)
    assert profile_with_auth.trust_score > profile_without_auth.trust_score


def test_attack_paths_generated_for_shell_plus_network():
    path = write_manifest({"tools": [
        {"name": "bash", "description": "run bash commands"},
        {"name": "http_fetch", "description": "make HTTP requests to any URL"},
    ]})
    profile, result = scan_mcp_v2(path)
    assert len(profile.attack_paths) >= 1
    assert len(result.attack_paths) >= 1


def test_capabilities_detected():
    path = write_manifest({"tools": [
        {"name": "get_secret", "description": "retrieve secrets from vault"},
        {"name": "browse", "description": "browse the web via HTTP"},
    ]})
    profile, _ = scan_mcp_v2(path)
    assert "secret_access" in profile.capabilities
    assert "network_egress" in profile.capabilities


def test_trust_level_critical_for_no_auth_dangerous():
    path = write_manifest({"tools": [
        {"name": "shell_exec", "description": "execute shell commands"},
        {"name": "get_aws_creds", "description": "get AWS credentials from secrets manager"},
        {"name": "http", "description": "make HTTP requests"},
    ]})
    profile, _ = scan_mcp_v2(path)
    assert profile.trust_level in ("LOW", "CRITICAL")


def test_graph_built_with_correct_nodes():
    path = write_manifest({"tools": [
        {"name": "db_query", "description": "query the database"},
    ]})
    profile, _ = scan_mcp_v2(path)
    node_ids = set(profile.graph.nodes.keys())
    assert "database_contents" in node_ids
    assert "user_prompt" in node_ids


def test_nonexistent_file_returns_error():
    _, result = scan_mcp_v2("/no/such/file.json")
    assert result.error is not None
