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
    (Path(tmpdir) / "server.json").write_text('''
{"name": "test-server", "tools": [{"name": "run_shell", "description": "execute commands"}]}
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
