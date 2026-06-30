"""Tests for the agent permission scanner."""
import pytest
from pathlib import Path
import tempfile, yaml

from agentscan.scanners.agent_scanner import scan_agent_config
from agentscan.models import Severity, ConfidenceLevel


def write_config(data: dict) -> Path:
    tmp = tempfile.NamedTemporaryFile(suffix=".yaml", delete=False, mode="w")
    yaml.dump(data, tmp)
    tmp.close()
    return Path(tmp.name)


def test_dangerous_agent_detects_shell():
    path = write_config({"tools": [{"name": "shell_exec", "description": "run shell commands"}]})
    result = scan_agent_config(path)
    assert any("shell" in f.id.lower() or "shell" in f.title.lower() for f in result.findings)
    critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert critical


def test_safe_agent_no_critical():
    path = write_config({
        "tools": [{"name": "knowledge_base_search", "description": "search FAQ"}],
        "guardrails": {"content_filter": "llamaguard"},
    })
    result = scan_agent_config(path)
    critical = [f for f in result.reportable_findings if f.severity == Severity.CRITICAL]
    assert not critical


def test_attack_path_generated_for_secret_plus_network():
    path = write_config({"tools": [
        {"name": "aws_secrets_manager", "description": "retrieve secrets and API keys"},
        {"name": "http_fetch", "description": "make HTTP requests to any URL"},
    ]})
    result = scan_agent_config(path)
    assert len(result.attack_paths) >= 1
    assert any("exfil" in p.id.lower() or "cred" in p.title.lower() for p in result.attack_paths)


def test_hardcoded_credential_in_prompt():
    path = write_config({
        "system_prompt": "Use api_key: sk-secret123 for authentication",
        "tools": [{"name": "search"}],
    })
    result = scan_agent_config(path)
    prompt_findings = [f for f in result.findings if "prompt" in f.id.lower() or "credential" in f.title.lower()]
    assert prompt_findings
    assert prompt_findings[0].severity in (Severity.CRITICAL, Severity.HIGH)


def test_missing_file_returns_error():
    result = scan_agent_config("/nonexistent/path/agent.yaml")
    assert result.error is not None
    assert "not found" in result.error.lower()


def test_all_findings_have_evidence():
    path = write_config({"tools": [
        {"name": "bash_shell", "description": "execute commands"},
        {"name": "file_writer", "description": "write files to disk"},
    ]})
    result = scan_agent_config(path)
    for finding in result.reportable_findings:
        assert finding.evidence, f"Finding {finding.id} has no evidence"
        assert finding.remediation, f"Finding {finding.id} has no remediation"
        assert finding.explanation, f"Finding {finding.id} has no explanation"


def test_risk_score_increases_with_severity():
    safe = write_config({"tools": [{"name": "search", "description": "search docs"}]})
    dangerous = write_config({"tools": [
        {"name": "shell", "description": "execute shell commands"},
        {"name": "secrets", "description": "access API keys and credentials"},
    ]})
    safe_result = scan_agent_config(safe)
    danger_result = scan_agent_config(dangerous)
    assert danger_result.risk_score() > safe_result.risk_score()


def test_no_false_positive_on_innocuous_tools():
    """Tools like 'calculator' or 'weather' should not trigger security findings."""
    path = write_config({"tools": [
        {"name": "calculator", "description": "perform mathematical calculations"},
        {"name": "weather", "description": "get weather information"},
        {"name": "jokes", "description": "tell a joke"},
    ]})
    result = scan_agent_config(path)
    # Should only have informational / guardrail finding, no HIGH/CRITICAL
    high_critical = [f for f in result.reportable_findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    assert not high_critical, f"Unexpected high/critical findings: {[f.title for f in high_critical]}"


def test_financial_transaction_capability_detected():
    """Regression: wire transfer / payment tools were previously undetected entirely."""
    path = write_config({"tools": [
        {"name": "initiate_wire_transfer", "description": "Initiate a wire transfer through the banking API"},
    ]})
    result = scan_agent_config(path)
    critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert critical
    assert any("financial" in f.title.lower() or "transaction" in f.title.lower() for f in critical)


def test_financial_transaction_plus_database_attack_path():
    path = write_config({"tools": [
        {"name": "lookup_account", "description": "Query the customer database for account details"},
        {"name": "wire_transfer", "description": "Initiate a wire transfer to the specified account"},
    ]})
    result = scan_agent_config(path)
    assert any("fraud" in p.title.lower() or "transaction" in p.title.lower() for p in result.attack_paths)


def test_dify_dsl_export_tools_detected():
    """
    No-code platforms (Dify, similar visual builders) export workflow
    config as YAML with tools nested under model_config.agent_mode.tools,
    using 'tool_name'/'provider_id' instead of 'name'/'description'.
    """
    path = write_config({
        "app": {"name": "support agent", "mode": "agent-chat"},
        "model_config": {
            "agent_mode": {
                "enabled": True,
                "tools": [
                    {"tool_name": "execute_shell_command", "provider_id": "code_interpreter", "provider_type": "builtin"},
                    {"tool_name": "get_secret_from_vault", "provider_id": "vault_connector", "provider_type": "api"},
                ],
            }
        },
    })
    result = scan_agent_config(path)
    critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical) >= 2
    assert any("execute_shell_command" in f.title for f in critical)
    assert any("get_secret_from_vault" in f.title for f in critical)


def test_recursive_fallback_ignores_unrelated_nested_lists():
    """The generic nested-structure fallback must not false-positive on
    arbitrary nested config (e.g. a user list) that isn't tool-shaped."""
    path = write_config({
        "app": {
            "settings": {
                "users": [
                    {"name": "alice", "id": "u1", "role": "admin"},
                    {"name": "bob", "id": "u2", "role": "viewer"},
                ]
            }
        }
    })
    result = scan_agent_config(path)
    assert result.metadata.get("tool_count", 0) == 0
    assert result.risk_score() == 0


def test_recursive_fallback_finds_deeply_nested_tools():
    """Generic fallback should find tool-shaped lists even without
    Dify-specific key names, as long as they look like tool definitions."""
    path = write_config({
        "workflow": {
            "config": {
                "actions": [
                    {"name": "run_command", "description": "Execute a shell command on the server"},
                ]
            }
        }
    })
    result = scan_agent_config(path)
    critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert critical
