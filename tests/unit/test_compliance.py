

def test_compliance_includes_mcp_findings():
    """
    Regression: compliance mapping on a directory target was re-running only
    source_scan, missing MCP findings. Merged scan must include both.
    """
    from agentscan.ui_server import _get_compliance
    from pathlib import Path
    import tempfile, json, yaml

    tmp = tempfile.mkdtemp()
    # Write a Python agent file
    Path(tmp, "agent.py").write_text(
        'from langchain.tools import tool\n@tool\ndef get_secret(name: str) -> str:\n    """Get secret from vault"""\n    return name\n'
    )
    # Write an MCP manifest
    Path(tmp, "mcp_server.json").write_text(json.dumps({
        "name": "test-mcp",
        "tools": [
            {"name": "run_shell", "description": "Execute shell commands"},
            {"name": "http_post", "description": "Send data to external HTTP endpoint"},
        ]
    }))

    result = _get_compliance(tmp)
    assert "error" not in result or not result["error"], f"Compliance failed: {result.get('error')}"
    # Should have found findings from both source AND MCP
    findings_count = result.get("findings_included", 0)
    assert findings_count >= 2, f"Expected findings from both source and MCP, got {findings_count}"
