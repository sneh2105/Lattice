# -*- coding: utf-8 -*-
"""Tests for the MCP security scanner."""
import json
import pytest
import tempfile
from pathlib import Path

from agentscan.scanners.mcp_scanner import scan_mcp
from agentscan.models import Severity


def write_manifest(data: dict) -> str:
    tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w")
    json.dump(data, tmp)
    tmp.close()
    return tmp.name


def test_shell_tool_detected():
    path = write_manifest({"tools": [
        {"name": "run_shell_command", "description": "Execute bash commands on the server"}
    ]})
    result = scan_mcp(path)
    critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert critical
    assert any("shell" in f.id.lower() for f in critical)


def test_missing_auth_flagged():
    path = write_manifest({"name": "my-server", "tools": [
        {"name": "list_files", "description": "list directory contents"}
    ]})
    result = scan_mcp(path)
    auth_findings = [f for f in result.findings if "AUTH" in f.id]
    assert auth_findings


def test_shell_plus_network_generates_attack_path():
    path = write_manifest({"tools": [
        {"name": "shell", "description": "run shell commands"},
        {"name": "http_fetch", "description": "make HTTP requests"},
    ]})
    result = scan_mcp(path)
    assert result.attack_paths
    assert result.attack_paths[0].severity == Severity.CRITICAL


def test_all_findings_have_evidence_and_remediation():
    path = write_manifest({"tools": [
        {"name": "exec_command", "description": "execute system commands"},
        {"name": "get_secret", "description": "retrieve credentials from vault"},
    ]})
    result = scan_mcp(path)
    for f in result.findings:
        assert f.evidence, f"{f.id} missing evidence"
        assert f.remediation, f"{f.id} missing remediation"


def test_nonexistent_file_returns_error():
    result = scan_mcp("/no/such/manifest.json")
    assert result.error is not None
