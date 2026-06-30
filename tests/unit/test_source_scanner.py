"""Tests for the real source-code AST scanner — no YAML required."""
import tempfile
from pathlib import Path
import pytest
from agentscan.scanners.source_scanner import scan_source, extract_tools_from_file
from agentscan.models import Severity


def write_py(code: str) -> Path:
    tmp = tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w")
    tmp.write(code)
    tmp.close()
    return Path(tmp.name)


def test_langchain_tool_decorator_detected():
    path = write_py('''
from langchain_core.tools import tool

@tool
def run_shell(cmd: str) -> str:
    """Execute a shell command on the host."""
    return "done"
''')
    result = scan_source(str(path))
    assert result.scanner_type == "source_scanner"
    critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert critical


def test_class_based_tool_detected():
    path = write_py('''
class GetSecretTool(BaseTool):
    name = "get_secret"
    description = "Retrieve API keys and credentials from the vault"
''')
    result = scan_source(str(path))
    secret_findings = [f for f in result.findings if "secret" in f.title.lower()]
    assert secret_findings


def test_autogen_register_function_detected():
    path = write_py('''
def search_web(query: str) -> str:
    return "results"

autogen.register_function(
    search_web,
    caller=assistant,
    executor=user_proxy,
    name="search_web",
    description="Search the web for information",
)
''')
    result = scan_source(str(path))
    assert result.metadata.get("tools_found", 0) >= 1


def test_safe_function_no_critical_findings():
    path = write_py('''
from langchain_core.tools import tool

@tool
def get_weather(city: str) -> str:
    """Look up the current weather for a city."""
    return f"Sunny in {city}"
''')
    result = scan_source(str(path))
    critical = [f for f in result.reportable_findings if f.severity == Severity.CRITICAL]
    assert not critical


def test_no_tools_found_returns_info():
    path = write_py('''
def regular_function(x):
    return x + 1
''')
    result = scan_source(str(path))
    assert result.metadata.get("tools_found", 0) == 0 or not result.findings or \
           result.findings[0].severity == Severity.INFO


def test_directory_scan_finds_multiple_files():
    import os
    tmpdir = tempfile.mkdtemp()
    (Path(tmpdir) / "agent1.py").write_text('''
from langchain_core.tools import tool

@tool
def shell_exec(cmd: str) -> str:
    """Run a shell command."""
    return ""
''')
    (Path(tmpdir) / "agent2.py").write_text('''
from langchain_core.tools import tool

@tool
def get_secrets(name: str) -> str:
    """Retrieve credentials from secrets manager."""
    return ""
''')
    result = scan_source(tmpdir)
    assert result.metadata.get("tools_found", 0) == 2


def test_nonexistent_path_returns_error():
    result = scan_source("/no/such/path.py")
    assert result.error is not None


def test_attack_path_built_from_source():
    path = write_py('''
from langchain_core.tools import tool

@tool
def get_aws_secret(name: str) -> str:
    """Retrieve secrets and API keys from AWS Secrets Manager."""
    return ""

@tool
def make_http_request(url: str) -> str:
    """Make an HTTP request to any external URL."""
    return ""
''')
    result = scan_source(str(path))
    assert len(result.attack_paths) >= 1


def test_findings_include_file_line_location():
    path = write_py('''
from langchain_core.tools import tool

@tool
def shell_exec(cmd: str) -> str:
    """Execute shell commands."""
    return ""
''')
    result = scan_source(str(path))
    assert result.findings
    assert any(":" in f.title for f in result.findings)  # file:line in title
