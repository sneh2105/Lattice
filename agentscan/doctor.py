"""
agentscan doctor
=================
Environment detection and first-run diagnostics.

Solves the actual onboarding failure mode: someone clones the repo and
doesn't know what to point AgentScan at. This command scans the current
directory (or a given path) and reports exactly what it found, what it
can analyse, and why anything couldn't be analysed.

Zero side effects — read-only detection, no scanning performed here.
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class DetectionResult:
    label: str
    found: bool
    detail: str = ""
    suggested_command: str = ""
    severity: str = "info"   # "ok" | "warn" | "info"


FRAMEWORK_SIGNATURES: dict[str, list[str]] = {
    "LangChain / LangGraph": [r"from langchain", r"from langgraph", r"langchain_core\.tools"],
    "CrewAI":                [r"from crewai", r"import crewai"],
    "AutoGen":                [r"import autogen", r"from autogen", r"register_function"],
    "OpenAI Agents SDK":      [r"from openai_agents", r"function_tool"],
    "Google ADK":             [r"from google\.adk", r"google\.generativeai"],
    "Semantic Kernel":        [r"import semantic_kernel", r"sk\.kernel_function"],
    "Amazon Bedrock Agents":  [r"bedrock-agent-runtime", r"boto3\.client\([\"']bedrock"],
}

TOOL_DECORATOR_PATTERNS = [r"@tool\b", r"@function_tool\b", r"@sk\.kernel_function", r"register_function\("]


def _scan_text_files(root: Path, max_files: int = 800) -> tuple[list[Path], str]:
    """Read all .py/.yaml/.yml/.json files under root, return paths + concatenated content (truncated)."""
    skip = {"venv", ".venv", "node_modules", "__pycache__", ".git", "site-packages"}
    files = []
    content_parts = []
    for ext in ("*.py", "*.yaml", "*.yml", "*.json"):
        for f in root.rglob(ext):
            if any(s in f.parts for s in skip):
                continue
            files.append(f)
            if len(files) > max_files:
                break
            try:
                content_parts.append(f.read_text(encoding="utf-8", errors="ignore")[:5000])
            except Exception:
                pass
    return files, "\n".join(content_parts)


def run_doctor(path: str = ".") -> list[DetectionResult]:
    """Run all detections against the given path. Returns ordered results."""
    root = Path(path).resolve()
    results: list[DetectionResult] = []

    if not root.exists():
        results.append(DetectionResult("Target path", False, f"'{path}' does not exist", severity="warn"))
        return results

    results.append(DetectionResult(
        "Target directory", True, str(root), severity="ok"
    ))

    py_files = [f for f in root.rglob("*.py") if not any(
        s in f.parts for s in {"venv", ".venv", "node_modules", "__pycache__", ".git"}
    )]
    yaml_files = [f for f in root.rglob("*.yaml")] + [f for f in root.rglob("*.yml")]
    json_files = [f for f in root.rglob("*.json") if not any(
        s in f.parts for s in {"venv", ".venv", "node_modules", "__pycache__", ".git"}
    )]

    files, content = _scan_text_files(root)

    # Framework detection
    detected_frameworks = []
    for name, patterns in FRAMEWORK_SIGNATURES.items():
        if any(re.search(p, content) for p in patterns):
            detected_frameworks.append(name)

    if detected_frameworks:
        results.append(DetectionResult(
            "Agent frameworks detected", True,
            ", ".join(detected_frameworks),
            suggested_command=f"agentscan source {path}",
            severity="ok",
        ))
    else:
        results.append(DetectionResult(
            "Agent frameworks detected", False,
            "No known framework imports found (LangChain, CrewAI, AutoGen, OpenAI Agents SDK, Google ADK, Semantic Kernel, Bedrock)",
            severity="info",
        ))

    # Tool count estimate
    tool_matches = sum(len(re.findall(p, content)) for p in TOOL_DECORATOR_PATTERNS)
    if tool_matches > 0:
        results.append(DetectionResult(
            "Tool definitions discovered", True,
            f"~{tool_matches} tool decorator(s)/registration(s) found across {len(py_files)} Python file(s)",
            suggested_command=f"agentscan source {path}",
            severity="ok",
        ))
    else:
        results.append(DetectionResult(
            "Tool definitions discovered", False,
            f"No @tool / @function_tool / register_function patterns found in {len(py_files)} Python file(s)",
            severity="info",
        ))

    # YAML/JSON agent configs (exclude CI workflow files, which always mention "tool"/"agent" incidentally)
    agent_yaml_candidates = []
    for f in yaml_files:
        if ".github" in f.parts or "workflows" in f.parts:
            continue
        try:
            text = f.read_text(errors="ignore")
            if re.search(r"\btools?\s*:", text, re.IGNORECASE) or re.search(r"\bcapabilit", text, re.IGNORECASE):
                agent_yaml_candidates.append(f)
        except Exception:
            pass
    if agent_yaml_candidates:
        results.append(DetectionResult(
            "Declarative agent config(s)", True,
            ", ".join(str(f.relative_to(root)) for f in agent_yaml_candidates[:5]),
            suggested_command=f"agentscan agent {agent_yaml_candidates[0].relative_to(root)}",
            severity="ok",
        ))
    else:
        results.append(DetectionResult(
            "Declarative agent config(s)", False,
            "No YAML/JSON files matching agent/tool patterns",
            severity="info",
        ))

    # MCP servers — look for the characteristic {"tools": [{"name": ..., "description": ...}]} shape
    mcp_candidates = []
    for f in json_files:
        try:
            text = f.read_text(errors="ignore")
            if re.search(r'"tools"\s*:\s*\[', text) and re.search(r'"name"\s*:', text) and re.search(r'"description"\s*:', text):
                mcp_candidates.append(f)
        except Exception:
            pass
    if mcp_candidates:
        results.append(DetectionResult(
            "MCP server manifest(s)", True,
            ", ".join(str(f.relative_to(root)) for f in mcp_candidates[:5]),
            suggested_command=f"agentscan mcp {mcp_candidates[0].relative_to(root)}",
            severity="ok",
        ))
    else:
        results.append(DetectionResult(
            "MCP server manifest(s)", False,
            "No JSON files matching MCP tool/inputSchema structure",
            severity="info",
        ))

    # requirements.txt / pyproject for dependency context
    dep_files = list(root.glob("requirements*.txt")) + list(root.glob("pyproject.toml"))
    if dep_files:
        results.append(DetectionResult(
            "Dependency manifest", True,
            ", ".join(f.name for f in dep_files),
            severity="ok",
        ))

    # Runtime tracing check — look for AgentScanMonitor / callback usage
    has_runtime_hook = bool(re.search(r"AgentScan(Monitor|LangChainCallback|CrewCallback|AutoGenHook|OpenAIHook)", content))
    results.append(DetectionResult(
        "Runtime tracing configured", has_runtime_hook,
        "AgentScan runtime SDK hooks found in code" if has_runtime_hook else
        "No AgentScan runtime monitoring hooks found — static scanning only",
        suggested_command=None if has_runtime_hook else "see docs/ADVANCED.md for runtime SDK integration",
        severity="ok" if has_runtime_hook else "warn",
    ))

    return results


def render_doctor_report(results: list[DetectionResult]) -> str:
    RED, ORANGE, GREEN, DIM, BOLD, CYAN, RESET = (
        "\033[91m", "\033[33m", "\033[92m", "\033[2m", "\033[1m", "\033[96m", "\033[0m"
    )
    import sys
    use_colour = sys.stdout.isatty()
    def c(code, s): return f"{code}{s}{RESET}" if use_colour else s

    lines = []
    lines.append("")
    lines.append(c(BOLD + CYAN, "  AgentScan Doctor — environment check"))
    lines.append("")

    suggestions = []
    for r in results:
        if r.severity == "ok":
            icon = c(GREEN, "✔")
        elif r.severity == "warn":
            icon = c(ORANGE, "⚠")
        else:
            icon = c(DIM, "○") if not r.found else c(GREEN, "✔")

        lines.append(f"  {icon} {c(BOLD, r.label)}")
        if r.detail:
            lines.append(f"      {c(DIM, r.detail)}")
        if r.suggested_command:
            suggestions.append(r.suggested_command)

    lines.append("")
    if suggestions:
        seen = []
        for s in suggestions:
            if s not in seen:
                seen.append(s)
        lines.append(c(BOLD, "  Suggested next step(s):"))
        for s in seen[:3]:
            lines.append(f"    {c(CYAN, '$')} {s}")
    else:
        lines.append(c(ORANGE, "  No scannable agent code or configs found in this path."))
        lines.append(f"  {c(DIM, 'Try: agentscan agent examples/agent_configs/dangerous_agent.yaml (bundled example)')}")
    lines.append("")
    return "\n".join(lines)
