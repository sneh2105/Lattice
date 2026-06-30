"""
MCP Security Scanner
====================
Analyses MCP (Model Context Protocol) server manifests for dangerous tool definitions,
excessive permissions, trust boundary violations, and supply chain risks.

Supports:
  - Local manifest files (JSON / YAML)
  - Live MCP server introspection via HTTP (tools/list endpoint)
"""

from __future__ import annotations
import json
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any

import yaml

from agentscan.models import (
    AttackPath, ConfidenceLevel, Evidence, Finding, ScanResult, Severity
)

# Tool capability patterns for MCP tool definitions
MCP_DANGEROUS_TOOL_PATTERNS: list[dict] = [
    {
        "id": "MCP-SHELL",
        "keywords": ["shell", "bash", "exec", "terminal", "command", "subprocess", "run"],
        "severity": Severity.CRITICAL,
        "title": "MCP tool exposes shell execution",
        "explanation": (
            "This MCP tool appears to provide shell or command execution capability. "
            "Any agent connecting to this server can be manipulated into running "
            "arbitrary OS commands via prompt injection or malicious instructions."
        ),
        "impact": "Full host compromise via arbitrary command execution",
        "remediation": (
            "Remove shell execution tools from the MCP server if possible. "
            "If required, implement strict command allowlisting, sandboxing (e.g. gVisor/seccomp), "
            "and audit logging for every invocation."
        ),
        "mitre": ["AML.T0017", "AML.T0048"],
    },
    {
        "id": "MCP-SECRETS",
        "keywords": ["secret", "credential", "api_key", "token", "vault", "ssm", "password", "keychain"],
        "severity": Severity.CRITICAL,
        "title": "MCP tool can access secrets or credentials",
        "explanation": (
            "This MCP tool grants access to secrets, credentials, or API keys. "
            "An attacker who injects a malicious prompt can instruct the agent to "
            "retrieve and exfiltrate these credentials."
        ),
        "impact": "Credential theft leading to account or infrastructure compromise",
        "remediation": (
            "Scope credential access to the minimum required secret(s). "
            "Use purpose-built secret injection (not agent-accessible vaults) where possible. "
            "Log and alert on every secret retrieval."
        ),
        "mitre": ["AML.T0051"],
    },
    {
        "id": "MCP-FILE-WRITE",
        "keywords": ["write_file", "file_write", "create_file", "delete_file", "move_file", "filesystem"],
        "severity": Severity.HIGH,
        "title": "MCP tool has filesystem write access",
        "explanation": (
            "This MCP tool can write, create, or delete files on the host filesystem. "
            "Combined with a code execution tool, this enables persistence attacks."
        ),
        "impact": "Malicious file creation, config manipulation, or persistence",
        "remediation": "Restrict filesystem tools to specific directories via allowlisting. Use read-only mounts where possible.",
        "mitre": ["AML.T0048"],
    },
    {
        "id": "MCP-NET",
        "keywords": ["http", "fetch", "request", "curl", "browse", "web", "url", "network"],
        "severity": Severity.MEDIUM,
        "title": "MCP tool can make network requests",
        "explanation": (
            "This MCP tool can make outbound HTTP or network requests. "
            "This is an exfiltration vector: an attacker can use it to send "
            "data to an external server."
        ),
        "impact": "Data exfiltration, SSRF, C2 beaconing",
        "remediation": "Restrict network tool to an allowlist of domains. Block requests to private IP ranges (SSRF prevention).",
        "mitre": ["AML.T0040"],
    },
    {
        "id": "MCP-CODE-EXEC",
        "keywords": ["eval", "python_repl", "code", "interpret", "execute_code", "run_code", "notebook"],
        "severity": Severity.CRITICAL,
        "title": "MCP tool executes arbitrary code",
        "explanation": "This MCP tool can evaluate or execute code, enabling arbitrary code execution within the agent's runtime.",
        "impact": "Arbitrary code execution within agent context",
        "remediation": "Sandbox code execution tools in isolated environments (Docker, Firecracker, WASM). Never run alongside secret-access tools.",
        "mitre": ["AML.T0017"],
    },
]


def _normalise(s: str) -> str:
    return s.lower().replace("-", "_").replace(" ", "_")


def _analyse_tool(tool: dict) -> list[Finding]:
    """Return findings for a single MCP tool definition."""
    findings = []
    tool_name = tool.get("name", "unnamed")
    description = tool.get("description", "")
    haystack = _normalise(tool_name) + " " + _normalise(description)

    for pattern in MCP_DANGEROUS_TOOL_PATTERNS:
        if any(kw in haystack for kw in pattern["keywords"]):
            # Check input schema for additional signals
            schema = tool.get("inputSchema", tool.get("input_schema", {}))
            schema_str = json.dumps(schema).lower() if schema else ""

            # Require at least one keyword match in name+description OR schema
            confidence = ConfidenceLevel.HIGH if any(kw in haystack for kw in pattern["keywords"][:2]) else ConfidenceLevel.MEDIUM

            findings.append(Finding(
                id=f"{pattern['id']}-{_normalise(tool_name)[:20].upper()}",
                title=f"{pattern['title']}: '{tool_name}'",
                severity=pattern["severity"],
                confidence=confidence,
                scanner="mcp_scanner",
                explanation=pattern["explanation"],
                impact=pattern["impact"],
                remediation=pattern["remediation"],
                evidence=[
                    Evidence(
                        source="mcp_tool_definition",
                        field=f"tools[name={tool_name!r}]",
                        observed_value={"name": tool_name, "description": description[:200]},
                        explanation=f"Tool name/description matched keywords: {[k for k in pattern['keywords'] if k in haystack]}"
                    )
                ],
                mitre_atlas=pattern["mitre"],
                tags=["mcp-tool", pattern["id"]],
            ))

    return findings


def _check_server_metadata(manifest: dict) -> list[Finding]:
    """Check server-level metadata for risk signals."""
    findings = []

    # Check for overly broad permission declarations
    permissions = manifest.get("permissions", manifest.get("scopes", []))
    if isinstance(permissions, list):
        dangerous_perms = [p for p in permissions if any(
            kw in str(p).lower() for kw in ["*", "admin", "root", "all", "write", "exec"]
        )]
        if dangerous_perms:
            findings.append(Finding(
                id="MCP-PERMS-BROAD",
                title="MCP server requests overly broad permissions",
                severity=Severity.HIGH,
                confidence=ConfidenceLevel.HIGH,
                scanner="mcp_scanner",
                explanation=(
                    "The MCP server manifest declares broad or wildcard permissions. "
                    "This violates least-privilege and means any agent connecting to "
                    "this server inherits these permissions."
                ),
                impact="Over-privileged agent access to resources beyond task scope",
                remediation="Scope permissions to the minimum required for each specific tool. Avoid wildcards.",
                evidence=[Evidence(
                    source="server_manifest",
                    field="permissions",
                    observed_value=dangerous_perms,
                    explanation="Wildcard or admin-level permission strings detected"
                )],
                mitre_atlas=["AML.T0048"],
                tags=["mcp-permissions"],
            ))

    # Check for missing authentication requirement
    auth = manifest.get("auth", manifest.get("authentication", manifest.get("security")))
    if auth is None and manifest.get("tools"):
        findings.append(Finding(
            id="MCP-AUTH-MISSING",
            title="MCP server has no authentication configured",
            severity=Severity.HIGH,
            confidence=ConfidenceLevel.MEDIUM,
            scanner="mcp_scanner",
            explanation=(
                "The MCP server manifest does not specify any authentication requirement. "
                "Without authentication, any agent (or attacker) can call this server's tools."
            ),
            impact="Unauthorised tool invocation by any network-accessible client",
            remediation="Implement OAuth 2.0 or API key authentication. The MCP spec supports OAuth — use it.",
            evidence=[Evidence(
                source="server_manifest",
                field="auth",
                observed_value=None,
                explanation="No 'auth', 'authentication', or 'security' key found in manifest"
            )],
            mitre_atlas=["AML.T0048"],
            tags=["mcp-auth"],
        ))

    return findings


def _load_from_url(url: str, timeout: int = 10) -> dict:
    """Fetch MCP tool list from a live server."""
    # Try standard MCP tools/list endpoint
    tools_url = url.rstrip("/") + "/tools/list"
    req = urllib.request.Request(
        tools_url,
        headers={"Content-Type": "application/json", "User-Agent": "AgentScan/0.1"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read())
    return data


def scan_mcp(target: str, timeout: int = 10) -> ScanResult:
    """
    Scan an MCP server or manifest file.

    target: path to a JSON/YAML manifest file, OR an HTTP(S) URL to a live MCP server
    """
    start = time.monotonic()
    manifest: dict = {}
    is_live = target.startswith("http://") or target.startswith("https://")

    if is_live:
        try:
            manifest = _load_from_url(target, timeout=timeout)
        except urllib.error.URLError as exc:
            return ScanResult(
                target=target,
                scanner_type="mcp_scanner",
                error=f"Could not connect to MCP server: {exc}",
            )
        except Exception as exc:
            return ScanResult(
                target=target,
                scanner_type="mcp_scanner",
                error=f"Failed to fetch MCP manifest: {exc}",
            )
    else:
        path = Path(target)
        if not path.exists():
            return ScanResult(target=target, scanner_type="mcp_scanner", error=f"File not found: {path}")
        try:
            text = path.read_text(encoding="utf-8")
            manifest = yaml.safe_load(text) if path.suffix in (".yaml", ".yml") else json.loads(text)
        except Exception as exc:
            return ScanResult(target=target, scanner_type="mcp_scanner", error=f"Parse error: {exc}")

    if not isinstance(manifest, dict):
        return ScanResult(target=target, scanner_type="mcp_scanner", error="Manifest root must be a mapping")

    findings: list[Finding] = []
    all_tool_caps: set[str] = set()

    # Server-level checks
    findings += _check_server_metadata(manifest)

    # Tool-level checks
    tools = manifest.get("tools", [])
    if not isinstance(tools, list):
        tools = []

    for tool in tools:
        tool_findings = _analyse_tool(tool)
        findings += tool_findings
        for f in tool_findings:
            all_tool_caps.update(f.tags)

    # Attack path: shell + network on same server
    cap_ids = {f.id.split("-")[1] for f in findings}
    attack_paths: list[AttackPath] = []

    if "SHELL" in cap_ids and "NET" in cap_ids:
        shell_f = [f for f in findings if "MCP-SHELL" in f.id]
        net_f = [f for f in findings if "MCP-NET" in f.id]
        attack_paths.append(AttackPath(
            id="MCP-PATH-SHELL-EXFIL",
            title="Full compromise path: shell execution + network egress on same MCP server",
            severity=Severity.CRITICAL,
            steps=shell_f + net_f,
            entry_point="Prompt injection via user message or malicious tool response",
            impact="Remote code execution with data exfiltration to attacker-controlled server",
            description=(
                "This MCP server exposes both shell execution and network request tools. "
                "An attacker who achieves prompt injection can chain these: "
                "execute commands to extract credentials, then POST them to an external server. "
                "This is a complete attack chain requiring no further capabilities."
            ),
            mitre_atlas=["AML.T0017", "AML.T0040", "AML.T0051"],
        ))

    if "SECRETS" in cap_ids and "NET" in cap_ids:
        attack_paths.append(AttackPath(
            id="MCP-PATH-CRED-EXFIL",
            title="Credential exfiltration path via MCP",
            severity=Severity.CRITICAL,
            steps=[f for f in findings if "MCP-SECRETS" in f.id or "MCP-NET" in f.id],
            entry_point="Prompt injection",
            impact="Cloud or service credentials exfiltrated",
            description=(
                "This MCP server exposes both a secrets/credential tool and a network tool. "
                "An injected prompt can instruct the agent to retrieve secrets and POST them externally."
            ),
            mitre_atlas=["AML.T0051", "AML.T0040"],
        ))

    elapsed_ms = int((time.monotonic() - start) * 1000)

    return ScanResult(
        target=target,
        scanner_type="mcp_scanner",
        findings=findings,
        attack_paths=attack_paths,
        metadata={
            "tool_count": len(tools),
            "server_name": manifest.get("name", manifest.get("server_name", "unknown")),
            "live_scan": is_live,
        },
        scan_duration_ms=elapsed_ms,
    )
