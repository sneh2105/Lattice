"""
Agent Permission Scanner
========================
Parses agent configuration files (YAML/JSON/TOML) and produces a risk report
covering tool permissions, privilege combinations, and dangerous capability patterns.

Low false-positive design:
  - Every finding requires structural evidence from the config itself.
  - Dangerous combinations (not just individual tools) trigger higher severity.
  - Plain-English explanation + remediation for every finding.
"""

from __future__ import annotations
import json
import re
import time
from pathlib import Path
from typing import Any

import yaml

from agentscan.models import (
    AttackPath, ConfidenceLevel, Evidence, Finding, ScanResult, Severity
)


# ---------------------------------------------------------------------------
# Capability taxonomy
# Capabilities are grouped by the access class they grant.
# The scanner maps tool names / keywords to these classes.
# ---------------------------------------------------------------------------

CAPABILITY_MAP: dict[str, dict] = {
    "shell_exec": {
        "keywords": ["shell", "bash", "exec", "subprocess", "terminal", "command", "run_code", "execute"],
        "severity": Severity.CRITICAL,
        "description": "Can execute arbitrary operating system commands",
        "impact": "Full host compromise: data exfiltration, persistence, lateral movement",
        "mitre": ["AML.T0017", "AML.T0048"],
        "cwe": ["CWE-78"],
    },
    "file_write": {
        "keywords": ["file_write", "write_file", "create_file", "filesystem", "disk_write", "save_file"],
        "severity": Severity.HIGH,
        "description": "Can write to the filesystem",
        "impact": "Malicious file creation, config tampering, persistence",
        "mitre": ["AML.T0048"],
        "cwe": ["CWE-73"],
    },
    "file_read": {
        "keywords": ["file_read", "read_file", "filesystem", "disk_read", "open_file", "cat"],
        "severity": Severity.MEDIUM,
        "description": "Can read arbitrary files from the filesystem",
        "impact": "Credential theft, source code exfiltration, config exposure",
        "mitre": ["AML.T0051"],
        "cwe": ["CWE-22"],
    },
    "network_egress": {
        "keywords": ["http", "request", "fetch", "web", "browser", "curl", "network", "internet", "url"],
        "severity": Severity.MEDIUM,
        "description": "Can make outbound network requests",
        "impact": "Data exfiltration, C2 communication, SSRF",
        "mitre": ["AML.T0040"],
        "cwe": ["CWE-918"],
    },
    "secret_access": {
        "keywords": ["secret", "vault", "credential", "api_key", "env", "ssm", "aws_secrets", "keychain"],
        "severity": Severity.CRITICAL,
        "description": "Can access secrets, credentials, or API keys",
        "impact": "Credential theft enabling further account compromise",
        "mitre": ["AML.T0051"],
        "cwe": ["CWE-522"],
    },
    "database": {
        "keywords": ["database", "db", "sql", "query", "postgres", "mysql", "mongo", "redis", "dynamo"],
        "severity": Severity.HIGH,
        "description": "Can query or modify databases",
        "impact": "Data exfiltration, data manipulation, injection attacks",
        "mitre": ["AML.T0048"],
        "cwe": ["CWE-89"],
    },
    "email_send": {
        "keywords": ["email", "send_mail", "smtp", "sendgrid", "ses", "mail"],
        "severity": Severity.MEDIUM,
        "description": "Can send emails",
        "impact": "Phishing, social engineering, data exfiltration via email",
        "mitre": ["AML.T0040"],
        "cwe": [],
    },
    "code_execution": {
        "keywords": ["python_repl", "code_interpreter", "eval", "repl", "jupyter", "notebook"],
        "severity": Severity.CRITICAL,
        "description": "Can execute arbitrary code in a runtime",
        "impact": "Full arbitrary code execution within agent context",
        "mitre": ["AML.T0017"],
        "cwe": ["CWE-95"],
    },
    "cloud_api": {
        "keywords": ["aws", "gcp", "azure", "s3", "ec2", "iam", "lambda", "cloud"],
        "severity": Severity.HIGH,
        "description": "Can call cloud provider APIs",
        "impact": "Cloud resource manipulation, data access, privilege escalation",
        "mitre": ["AML.T0048"],
        "cwe": [],
    },
}

# Dangerous capability combinations that together form attack paths
DANGEROUS_COMBINATIONS: list[dict] = [
    {
        "caps": {"secret_access", "network_egress"},
        "title": "Credential exfiltration path",
        "severity": Severity.CRITICAL,
        "description": (
            "The agent can read secrets AND make outbound network requests. "
            "This is a complete exfiltration path: an attacker who controls the agent's "
            "prompt (via prompt injection or malicious tool output) can instruct it to "
            "read credentials and POST them to an attacker-controlled server."
        ),
        "entry": "Prompt injection via user input or malicious tool output",
        "impact": "AWS/cloud credentials, API keys, or secrets exfiltrated to attacker",
        "mitre": ["AML.T0051", "AML.T0040"],
    },
    {
        "caps": {"shell_exec", "network_egress"},
        "title": "Remote code execution + exfiltration path",
        "severity": Severity.CRITICAL,
        "description": (
            "The agent can execute shell commands AND make network requests. "
            "Combined, this enables full reverse shell, C2 beaconing, or data exfiltration."
        ),
        "entry": "Prompt injection or malicious MCP tool response",
        "impact": "Host compromise with persistent attacker foothold",
        "mitre": ["AML.T0017", "AML.T0040"],
    },
    {
        "caps": {"file_write", "code_execution"},
        "title": "Persistent malware drop path",
        "severity": Severity.CRITICAL,
        "description": (
            "The agent can write files AND execute code. An attacker can instruct it to "
            "write malicious scripts and then execute them, achieving persistent compromise."
        ),
        "entry": "Malicious prompt or tool output",
        "impact": "Persistent backdoor or malware dropped on host",
        "mitre": ["AML.T0017", "AML.T0048"],
    },
    {
        "caps": {"cloud_api", "secret_access"},
        "title": "Cloud privilege escalation path",
        "severity": Severity.CRITICAL,
        "description": (
            "The agent can access cloud APIs AND read secrets. This enables privilege "
            "escalation: steal IAM credentials, then use them to access other cloud resources."
        ),
        "entry": "Prompt injection via user message",
        "impact": "Cloud account takeover via stolen IAM credentials",
        "mitre": ["AML.T0051", "AML.T0048"],
    },
    {
        "caps": {"database", "network_egress"},
        "title": "Database exfiltration path",
        "severity": Severity.HIGH,
        "description": (
            "The agent can query databases AND make outbound requests. "
            "An attacker can instruct it to dump sensitive tables and exfiltrate the data."
        ),
        "entry": "Prompt injection via user-supplied query",
        "impact": "Full database contents exfiltrated to attacker",
        "mitre": ["AML.T0051", "AML.T0040"],
    },
]


def _normalise(name: str) -> str:
    return name.lower().replace("-", "_").replace(" ", "_")


def _detect_capabilities(tool_name: str, tool_def: dict) -> set[str]:
    """Map a tool definition to a set of capability class names."""
    detected: set[str] = set()
    haystack = _normalise(tool_name)
    # Also check description and any 'permissions' field
    if isinstance(tool_def, dict):
        haystack += " " + _normalise(tool_def.get("description", ""))
        haystack += " " + _normalise(str(tool_def.get("permissions", "")))
        haystack += " " + _normalise(str(tool_def.get("type", "")))

    for cap_name, cap in CAPABILITY_MAP.items():
        if any(kw in haystack for kw in cap["keywords"]):
            detected.add(cap_name)
    return detected


def _extract_tools(config: dict) -> list[dict]:
    """
    Normalise tool lists from various agent config formats:
    - LangChain / AutoGen / CrewAI / OpenAI Assistants / custom
    """
    # Common top-level keys
    for key in ("tools", "tool_list", "capabilities", "plugins", "functions"):
        if key in config:
            raw = config[key]
            if isinstance(raw, list):
                tools = []
                for item in raw:
                    if isinstance(item, str):
                        tools.append({"name": item})
                    elif isinstance(item, dict):
                        tools.append(item)
                return tools

    # OpenAI Assistants format: {"tools": [{"type": "function", "function": {...}}]}
    if "assistant" in config and "tools" in config.get("assistant", {}):
        raw = config["assistant"]["tools"]
        return [{"name": t.get("function", {}).get("name", t.get("type", "unknown")), **t} for t in raw]

    return []


def _check_system_prompt(config: dict) -> list[Finding]:
    """Inspect system prompt for dangerous instruction patterns."""
    findings = []
    prompt = config.get("system_prompt", config.get("instructions", ""))
    if not isinstance(prompt, str) or not prompt:
        return findings

    dangerous_patterns = [
        (r"ignore\s+(previous|prior|above|all)\s+instructions", "Prompt injection susceptibility in system prompt",
         "The system prompt contains language that itself acknowledges or invites ignoring prior instructions. "
         "This pattern can be exploited via indirect prompt injection.",
         Severity.HIGH),
        (r"do\s+not\s+tell\s+the\s+user", "Hidden instruction in system prompt",
         "The system prompt instructs the agent to conceal information from the user, "
         "which can be abused to hide malicious actions.",
         Severity.MEDIUM),
        (r"(password|secret|api.?key|token)\s*[:=]\s*\S+", "Hardcoded credential in system prompt",
         "A credential or secret appears to be hardcoded directly in the system prompt. "
         "This will be visible in any logs, traces, or prompt leakage.",
         Severity.CRITICAL),
    ]

    for pattern, title, explanation, severity in dangerous_patterns:
        if re.search(pattern, prompt, re.IGNORECASE):
            findings.append(Finding(
                id=f"AGT-PROMPT-{title[:10].upper().replace(' ', '_')}",
                title=title,
                severity=severity,
                confidence=ConfidenceLevel.HIGH,
                scanner="agent_scanner",
                explanation=explanation,
                impact="Enables attacker to hijack agent behaviour or expose secrets",
                remediation="Remove sensitive data from system prompts. Use secure secret management. Audit prompt for injection-enabling language.",
                evidence=[Evidence(
                    source="system_prompt",
                    field="system_prompt",
                    observed_value=re.search(pattern, prompt, re.IGNORECASE).group(0),
                    explanation=f"Matched dangerous pattern: {pattern}"
                )],
                mitre_atlas=["AML.T0051"],
            ))
    return findings


def scan_agent_config(path: str | Path) -> ScanResult:
    """
    Main entry point for agent config scanning.

    Accepts YAML or JSON agent configuration files.
    Returns a ScanResult with findings and attack paths.
    """
    start = time.monotonic()
    path = Path(path)

    if not path.exists():
        return ScanResult(
            target=str(path),
            scanner_type="agent_scanner",
            error=f"File not found: {path}",
        )

    # Parse config
    try:
        text = path.read_text(encoding="utf-8")
        if path.suffix in (".yaml", ".yml"):
            config = yaml.safe_load(text)
        else:
            config = json.loads(text)
    except Exception as exc:
        return ScanResult(
            target=str(path),
            scanner_type="agent_scanner",
            error=f"Failed to parse config: {exc}",
        )

    if not isinstance(config, dict):
        return ScanResult(
            target=str(path),
            scanner_type="agent_scanner",
            error="Config root must be a mapping (dict)",
        )

    findings: list[Finding] = []
    all_caps: set[str] = set()
    cap_to_tools: dict[str, list[str]] = {}

    # 1. Scan each tool
    tools = _extract_tools(config)

    if not tools:
        findings.append(Finding(
            id="AGT-INFO-NO-TOOLS",
            title="No tools detected in config",
            severity=Severity.INFO,
            confidence=ConfidenceLevel.HIGH,
            scanner="agent_scanner",
            explanation="AgentScan could not find a tool list in this config. "
                        "This may mean the agent uses a format not yet supported, "
                        "or the agent has no tools (e.g. pure chat).",
            impact="None — informational only",
            remediation="Check that your config uses a supported key: 'tools', 'tool_list', 'capabilities', 'plugins', or 'functions'.",
        ))

    for tool in tools:
        tool_name = tool.get("name", tool.get("type", "unnamed_tool"))
        caps = _detect_capabilities(tool_name, tool)
        all_caps |= caps

        for cap in caps:
            cap_to_tools.setdefault(cap, []).append(tool_name)
            cap_info = CAPABILITY_MAP[cap]

            findings.append(Finding(
                id=f"AGT-CAP-{cap.upper()}-{_normalise(tool_name)[:20].upper()}",
                title=f"Tool '{tool_name}' grants {cap_info['description'].lower()}",
                severity=cap_info["severity"],
                confidence=ConfidenceLevel.HIGH,
                scanner="agent_scanner",
                explanation=(
                    f"The tool '{tool_name}' maps to the '{cap}' capability class. "
                    f"{cap_info['description']}. "
                    "By itself this may be intentional, but in combination with other "
                    "capabilities it can form dangerous attack paths (see attack paths below)."
                ),
                impact=cap_info["impact"],
                remediation=(
                    f"Review whether '{tool_name}' is required for the agent's task. "
                    "If so, scope its permissions as narrowly as possible (e.g. read-only paths, "
                    "allowlisted domains, specific DB tables). "
                    "Consider running the agent in a sandboxed environment."
                ),
                evidence=[Evidence(
                    source="tool_definition",
                    field=f"tools[name={tool_name!r}]",
                    observed_value=tool_name,
                    explanation=f"Tool name matched keywords for capability '{cap}': {cap_info['keywords'][:3]}"
                )],
                mitre_atlas=cap_info["mitre"],
                cwe=cap_info["cwe"],
                tags=["tool-permissions", cap],
            ))

    # 2. Check system prompt
    findings += _check_system_prompt(config)

    # 3. Check for missing safety controls
    has_guardrails = any(
        k in config
        for k in ("guardrails", "content_filter", "safety", "output_filter", "moderation")
    )
    if not has_guardrails and tools:
        findings.append(Finding(
            id="AGT-CTRL-NO-GUARDRAILS",
            title="No output guardrails configured",
            severity=Severity.MEDIUM,
            confidence=ConfidenceLevel.MEDIUM,
            scanner="agent_scanner",
            explanation=(
                "The agent config does not include any output safety controls or guardrails. "
                "Without guardrails, the agent may be manipulated into producing harmful outputs "
                "or leaking sensitive information."
            ),
            impact="Prompt injection, jailbreaks, and data leakage have no mitigation layer",
            remediation=(
                "Add a 'guardrails' section to your config referencing a content filter. "
                "Consider LlamaGuard, Nvidia NeMo Guardrails, or a custom output validator."
            ),
            evidence=[Evidence(
                source="config_structure",
                field="(missing)",
                observed_value=list(config.keys()),
                explanation="None of the expected guardrail keys were present in the config"
            )],
            mitre_atlas=["AML.T0054"],
            tags=["missing-control"],
        ))

    # 4. Build attack paths from dangerous capability combinations
    attack_paths: list[AttackPath] = []
    for combo in DANGEROUS_COMBINATIONS:
        required_caps = combo["caps"]
        if required_caps.issubset(all_caps):
            involved_findings = [
                f for f in findings
                if any(tag in f.tags for tag in required_caps)
            ]
            path_id = f"PATH-{'_'.join(sorted(required_caps))[:30].upper()}"
            attack_paths.append(AttackPath(
                id=path_id,
                title=combo["title"],
                severity=combo["severity"],
                steps=involved_findings,
                entry_point=combo["entry"],
                impact=combo["impact"],
                description=combo["description"],
                mitre_atlas=combo["mitre"],
            ))

    elapsed_ms = int((time.monotonic() - start) * 1000)

    return ScanResult(
        target=str(path),
        scanner_type="agent_scanner",
        findings=findings,
        attack_paths=attack_paths,
        metadata={
            "tool_count": len(tools),
            "capabilities_detected": sorted(all_caps),
            "cap_to_tools": cap_to_tools,
            "config_keys": list(config.keys()),
        },
        scan_duration_ms=elapsed_ms,
    )
