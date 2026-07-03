# -*- coding: utf-8 -*-
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
# Capability taxonomy and detection: imported from the canonical module.
# agentscan.scanners.capabilities is the SINGLE SOURCE OF TRUTH -- do not
# define keyword lists here. These names are re-exported for backward
# compatibility (source_scanner and tests import them from this module).
# ---------------------------------------------------------------------------
from agentscan.scanners.capabilities import (  # noqa: F401  (re-exported)
    CAPABILITY_MAP,
    DANGEROUS_COMBINATIONS,
    detect_capabilities as _detect_capabilities,
    detect_capabilities_with_reasons as _detect_capabilities_with_reasons,
    normalise as _normalise,
    shell_token_reason as _shell_token_reason,
    _has_shell_token_pair,
)


def _normalise_tool_item(item) -> dict | None:
    """Convert a tool entry from any known schema variant into {'name': ..., 'description': ...}."""
    if isinstance(item, str):
        return {"name": item}
    if not isinstance(item, dict):
        return None
    # Try every known "name" field across formats we've seen in the wild
    name = (
        item.get("name") or item.get("tool_name") or item.get("provider_id")
        or item.get("id") or item.get("function", {}).get("name") if isinstance(item.get("function"), dict) else None
    )
    if not name:
        name = item.get("name") or item.get("tool_name") or item.get("provider_id") or item.get("id")
    description = (
        item.get("description") or item.get("tool_description")
        or (item.get("function", {}).get("description") if isinstance(item.get("function"), dict) else "")
        or ""
    )
    if not name:
        return None
    return {"name": str(name), "description": str(description), **item}


def _extract_tools(config: dict) -> list[dict]:
    """
    Normalise tool lists from various agent config formats:
    - LangChain / AutoGen / CrewAI / OpenAI Assistants / custom
    - Dify DSL exports (model_config.agent_mode.tools -- no-code platform)
    - Generic nested no-code platform exports (recursive fallback)
    """
    # Common top-level keys
    for key in ("tools", "tool_list", "capabilities", "plugins", "functions"):
        if key in config:
            raw = config[key]
            if isinstance(raw, list):
                tools = [_normalise_tool_item(item) for item in raw]
                return [t for t in tools if t]

    # OpenAI Assistants format: {"tools": [{"type": "function", "function": {...}}]}
    if "assistant" in config and "tools" in config.get("assistant", {}):
        raw = config["assistant"]["tools"]
        return [{"name": t.get("function", {}).get("name", t.get("type", "unknown")), **t} for t in raw]

    # Dify DSL export: app.mode == agent-chat, tools nested under model_config.agent_mode.tools
    # Each entry uses 'tool_name' + 'provider_id' instead of 'name' + 'description'.
    model_config = config.get("model_config", {})
    agent_mode = model_config.get("agent_mode", {}) if isinstance(model_config, dict) else {}
    if isinstance(agent_mode, dict) and "tools" in agent_mode:
        raw = agent_mode["tools"]
        if isinstance(raw, list):
            tools = [_normalise_tool_item(item) for item in raw]
            return [t for t in tools if t]

    # Generic recursive fallback: search the whole config tree for any list whose
    # items look like tool definitions (have a name-like key AND a description-like key).
    # This catches other no-code platform export formats we haven't seen explicitly yet.
    found = _recursive_find_tool_list(config)
    if found:
        tools = [_normalise_tool_item(item) for item in found]
        return [t for t in tools if t]

    return []


def _recursive_find_tool_list(node, depth: int = 0, max_depth: int = 6) -> list | None:
    """Walk a nested dict/list structure looking for a list of tool-shaped dicts."""
    if depth > max_depth:
        return None
    if isinstance(node, list):
        if node and all(isinstance(i, dict) for i in node):
            name_keys = {"name", "tool_name", "provider_id", "id"}
            desc_keys = {"description", "tool_description"}
            if any(name_keys & set(i.keys()) for i in node) and \
               any((desc_keys & set(i.keys())) or "provider_type" in i for i in node):
                return node
        for item in node:
            result = _recursive_find_tool_list(item, depth + 1, max_depth)
            if result:
                return result
    elif isinstance(node, dict):
        for value in node.values():
            result = _recursive_find_tool_list(value, depth + 1, max_depth)
            if result:
                return result
    return None


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
            impact="None -- informational only",
            remediation="Check that your config uses a supported key: 'tools', 'tool_list', 'capabilities', 'plugins', or 'functions'.",
        ))

    for tool in tools:
        tool_name = tool.get("name", tool.get("type", "unnamed_tool"))
        cap_reasons = _detect_capabilities_with_reasons(tool_name, tool)
        caps = set(cap_reasons)
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
                    explanation=f"Capability '{cap}' assigned because: {cap_reasons[cap]}"
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
            # Dedupe by tool name: a tool matching multiple capability tags
            # would otherwise appear twice in the chain (P2b fix).
            seen_tool_names: set[str] = set()
            involved_findings = []
            for f in findings:
                if any(tag in f.tags for tag in required_caps):
                    tool_key = f.title.split("'")[1] if "'" in f.title else f.id
                    if tool_key not in seen_tool_names:
                        seen_tool_names.add(tool_key)
                        involved_findings.append(f)
            path_id = "PATH-" + "_".join(sorted(required_caps))[:30].upper()
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
