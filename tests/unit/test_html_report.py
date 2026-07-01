# -*- coding: utf-8 -*-
"""Tests for the static HTML dashboard report generator."""
import tempfile
from pathlib import Path
import pytest
from agentscan.outputs.html_report import generate_html_report
from agentscan.scanners.agent_scanner import scan_agent_config
import yaml


def make_dangerous_config() -> str:
    tmp = tempfile.NamedTemporaryFile(suffix=".yaml", delete=False, mode="w")
    yaml.dump({"tools": [
        {"name": "shell_exec", "description": "execute shell commands"},
        {"name": "aws_secrets", "description": "retrieve secrets and API keys"},
    ]}, tmp)
    tmp.close()
    return tmp.name


def test_html_report_generated():
    config = make_dangerous_config()
    result = scan_agent_config(config)
    out_dir = tempfile.mkdtemp()
    path = generate_html_report(result, str(Path(out_dir) / "report.html"))
    assert Path(path).exists()
    content = Path(path).read_text()
    assert "<!DOCTYPE html>" in content
    assert "AgentScan" in content


def test_html_report_contains_risk_score():
    config = make_dangerous_config()
    result = scan_agent_config(config)
    out_dir = tempfile.mkdtemp()
    path = generate_html_report(result, str(Path(out_dir) / "report.html"))
    content = Path(path).read_text()
    assert str(result.risk_score()) in content


def test_html_report_contains_findings():
    config = make_dangerous_config()
    result = scan_agent_config(config)
    out_dir = tempfile.mkdtemp()
    path = generate_html_report(result, str(Path(out_dir) / "report.html"))
    content = Path(path).read_text()
    for f in result.reportable_findings:
        assert f.title.split("'")[0] in content or f.id in content


def test_html_report_escapes_html_special_chars():
    config = make_dangerous_config()
    result = scan_agent_config(config)
    out_dir = tempfile.mkdtemp()
    path = generate_html_report(result, str(Path(out_dir) / "report.html"), title="<script>alert(1)</script>")
    content = Path(path).read_text()
    assert "<script>alert(1)</script>" not in content
    assert "&lt;script&gt;" in content


def test_html_report_handles_zero_findings():
    config = tempfile.NamedTemporaryFile(suffix=".yaml", delete=False, mode="w")
    yaml.dump({"tools": [{"name": "weather", "description": "get weather"}]}, config)
    config.close()
    result = scan_agent_config(config.name)
    out_dir = tempfile.mkdtemp()
    path = generate_html_report(result, str(Path(out_dir) / "report.html"))
    content = Path(path).read_text()
    assert Path(path).exists()


def test_html_report_path_adds_extension():
    config = make_dangerous_config()
    result = scan_agent_config(config)
    out_dir = tempfile.mkdtemp()
    path = generate_html_report(result, str(Path(out_dir) / "report"))  # no extension
    assert path.endswith(".html")
    assert Path(path).exists()


def test_cli_html_output_flag():
    """Integration: CLI --output html should produce a valid file."""
    import subprocess
    config = make_dangerous_config()
    out_dir = tempfile.mkdtemp()
    out_file = str(Path(out_dir) / "cli_report.html")
    result = subprocess.run(
        ["agentscan", "agent", config, "--output", "html", "--output-file", out_file],
        capture_output=True, text=True, encoding="utf-8"
    )
    assert Path(out_file).exists()
    assert "AgentScan Report" in result.stdout
