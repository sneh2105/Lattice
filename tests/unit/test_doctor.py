# -*- coding: utf-8 -*-
"""Tests for agentscan doctor -- environment detection."""
import tempfile
from pathlib import Path
import pytest
from agentscan.doctor import run_doctor, render_doctor_report


def test_doctor_detects_langchain_framework():
    tmpdir = tempfile.mkdtemp()
    (Path(tmpdir) / "agent.py").write_text('''
from langchain_core.tools import tool

@tool
def search(query: str) -> str:
    """Search something."""
    return ""
''')
    results = run_doctor(tmpdir)
    framework_result = next(r for r in results if r.label == "Agent frameworks detected")
    assert framework_result.found
    assert "LangChain" in framework_result.detail


def test_doctor_detects_no_framework_gracefully():
    tmpdir = tempfile.mkdtemp()
    (Path(tmpdir) / "plain.py").write_text("def regular_function(): pass")
    results = run_doctor(tmpdir)
    framework_result = next(r for r in results if r.label == "Agent frameworks detected")
    assert not framework_result.found


def test_doctor_detects_mcp_manifest():
    tmpdir = tempfile.mkdtemp()
    # Real MCP manifests have inputSchema on each tool -- that's what
    # distinguishes them from declarative agent configs (which don't).
    (Path(tmpdir) / "server.json").write_text('''
{
  "name": "test-mcp-server",
  "tools": [
    {
      "name": "run_shell",
      "description": "execute commands",
      "inputSchema": {"type": "object", "properties": {"cmd": {"type": "string"}}}
    }
  ]
}
''')
    results = run_doctor(tmpdir)
    mcp_result = next(r for r in results if r.label == "MCP server manifest(s)")
    assert mcp_result.found
    assert "server.json" in mcp_result.detail


def test_doctor_detects_yaml_agent_config():
    tmpdir = tempfile.mkdtemp()
    (Path(tmpdir) / "agent.yaml").write_text("tools:\n  - name: search\n")
    results = run_doctor(tmpdir)
    yaml_result = next(r for r in results if r.label == "Declarative agent config(s)")
    assert yaml_result.found


def test_doctor_excludes_github_workflow_yamls():
    tmpdir = tempfile.mkdtemp()
    (Path(tmpdir) / ".github" / "workflows").mkdir(parents=True)
    (Path(tmpdir) / ".github" / "workflows" / "ci.yml").write_text("name: CI\njobs:\n  test:\n    tool: pytest\n")
    results = run_doctor(tmpdir)
    yaml_result = next(r for r in results if r.label == "Declarative agent config(s)")
    assert not yaml_result.found


def test_doctor_nonexistent_path():
    results = run_doctor("/no/such/path/exists")
    assert results
    assert not results[0].found


def test_doctor_suggestions_are_deduplicated():
    tmpdir = tempfile.mkdtemp()
    (Path(tmpdir) / "agent.py").write_text('''
from langchain_core.tools import tool

@tool
def search(query: str) -> str:
    """Search something."""
    return ""

@tool
def fetch(url: str) -> str:
    """Fetch a URL."""
    return ""
''')
    results = run_doctor(tmpdir)
    report = render_doctor_report(results)
    # Should not show the same suggested command twice
    lines = [l for l in report.split("\n") if "agentscan source" in l]
    assert len(lines) <= 1


def test_doctor_render_produces_output():
    tmpdir = tempfile.mkdtemp()
    results = run_doctor(tmpdir)
    report = render_doctor_report(results)
    assert "AgentScan Doctor" in report
    assert len(report) > 0


def test_doctor_tool_count_matches_source_scanner():
    """
    Regression: doctor used regex patterns that drifted from source_scanner.
    Both must now return the same count for the same directory.
    """
    import subprocess, os
    from pathlib import Path
    tmpdir = tempfile.mkdtemp()
    (Path(tmpdir) / "agent.py").write_text(
        "from langchain.tools import tool\n\n"
        "@tool\ndef search(q: str) -> str:\n    \"\"\"Search the web.\"\"\"\n    return q\n\n"
        "@tool\ndef get_secret(name: str) -> str:\n    \"\"\"Retrieve a secret from the vault.\"\"\"\n    return name\n"
    )
    # Doctor count
    results = run_doctor(tmpdir)
    tool_result = next(r for r in results if r.label == "Tool definitions discovered")
    doctor_count = int(tool_result.detail.split()[0]) if tool_result.found else 0

    # Source scanner count
    from agentscan.scanners.source_scanner import scan_source
    scan = scan_source(tmpdir)
    source_count = scan.metadata.get("tools_found", 0)

    assert doctor_count == source_count, (
        f"doctor says {doctor_count} tools, source says {source_count} -- they must agree"
    )


def test_doctor_classifies_n8n_as_agent_config_not_mcp():
    """
    Regression: n8n workflow JSON was incorrectly listed under MCP servers.
    It must go to Declarative agent config(s) since it has no inputSchema.
    """
    tmpdir = tempfile.mkdtemp()
    (Path(tmpdir) / "workflow.json").write_text('''{
  "name": "Support Workflow",
  "nodes": [{"type": "n8n-nodes-base.agent", "parameters": {
    "tools": [
      {"name": "run_shell", "description": "Execute shell command"},
      {"name": "fetch_secret", "description": "Get a secret"}
    ]
  }}]
}''')
    results = run_doctor(tmpdir)
    mcp_result = next(r for r in results if r.label == "MCP server manifest(s)")
    agent_result = next(r for r in results if r.label == "Declarative agent config(s)")
    assert not mcp_result.found, "n8n workflow must NOT be classified as MCP"
    assert agent_result.found, "n8n workflow must be classified as agent config"
