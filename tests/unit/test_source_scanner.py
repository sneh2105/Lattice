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


def test_register_function_uses_real_docstring_not_just_summary():
    """
    Regression test: register_function()'s description= kwarg is often a vague
    LLM-facing summary. The actual function's docstring frequently contains the
    real risk signal and must be merged in, not ignored.
    """
    path = write_py('''
def run_terraform_apply(workspace: str) -> str:
    """Execute terraform apply against the specified infrastructure workspace."""
    import subprocess
    return subprocess.run(["terraform", "apply"], cwd=workspace).stdout

autogen.register_function(
    run_terraform_apply,
    caller=assistant,
    executor=executor,
    name="run_terraform_apply",
    description="Apply terraform infrastructure changes",
)
''')
    result = scan_source(str(path))
    critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert critical, "Should detect shell_exec from the function's own docstring, not just the vague description kwarg"


def test_nova_act_tool_decorator_detected():
    """
    Amazon Nova Act uses the same @tool decorator convention as LangChain/CrewAI
    (per AWS docs: https://docs.aws.amazon.com/nova-act/latest/userguide/tool-use.html)
    so it is detected without any Nova-Act-specific code.
    """
    path = write_py('''
from nova_act import tool

@tool
def fetch_aws_credentials(secret_name: str) -> str:
    """Retrieve AWS credentials from Secrets Manager for the workflow."""
    return "retrieved"
''')
    result = scan_source(str(path))
    critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert critical
    assert "langchain_crewai_or_nova_act" in result.metadata["frameworks_detected"]
