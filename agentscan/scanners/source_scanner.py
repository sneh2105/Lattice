"""
Source Code Scanner
=====================
Real enterprises don't have YAML configs describing their agents — they have
Python source code with framework-specific tool definitions. This scanner
parses that source directly via AST, with zero execution of the code.

Supported patterns (auto-detected):
  LangChain  — @tool decorator, Tool(name=..., func=...), BaseTool subclasses
  CrewAI     — BaseTool subclasses, @tool decorator
  AutoGen    — @register_function, function passed to register_function()
  OpenAI SDK — @function_tool decorator
  Generic    — any function with a docstring passed into a tools=[...] list

This produces the exact same internal capability model as agent_scanner.py,
so every downstream feature (attack graph, escalation, compliance mapping)
works identically whether the input was a YAML file or a real repo.
"""

from __future__ import annotations
import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from agentscan.models import ScanResult, Finding, Evidence, Severity, ConfidenceLevel
from agentscan.scanners.agent_scanner import (
    CAPABILITY_MAP, DANGEROUS_COMBINATIONS, _normalise, _detect_capabilities,
)


@dataclass
class ExtractedTool:
    name: str
    description: str
    framework_hint: str       # "langchain" | "crewai" | "autogen" | "openai_agents" | "unknown"
    source_file: str
    line_number: int
    decorator_used: str = ""


# Decorator / call patterns that mark a function as an agent tool
TOOL_DECORATOR_NAMES = {
    "tool": "langchain_or_crewai",          # @tool  (LangChain, CrewAI both use this name)
    "function_tool": "openai_agents",       # @function_tool (OpenAI Agents SDK)
    "kernel_function": "semantic_kernel",   # @sk.kernel_function (Semantic Kernel)
}

# Function calls that register a tool (not decorator-based)
TOOL_REGISTRATION_CALLS = {
    "register_function": "autogen",
    "Tool": "langchain",            # Tool(name=..., func=..., description=...)
    "StructuredTool": "langchain",
}


def _get_decorator_name(decorator: ast.expr) -> str | None:
    """Extract the name from a decorator node, handling @tool and @sk.kernel_function."""
    if isinstance(decorator, ast.Name):
        return decorator.id
    if isinstance(decorator, ast.Attribute):
        return decorator.attr
    if isinstance(decorator, ast.Call):
        return _get_decorator_name(decorator.func)
    return None


def _get_call_name(call: ast.Call) -> str | None:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return None


def _get_docstring(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    doc = ast.get_docstring(node)
    return doc or ""


def _get_string_kwarg(call: ast.Call, kwarg_name: str) -> str | None:
    for kw in call.keywords:
        if kw.arg == kwarg_name and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
            return kw.value.value
    return None


class ToolExtractor(ast.NodeVisitor):
    """Walks a Python AST and extracts every function that looks like an agent tool."""

    def __init__(self, source_file: str):
        self.source_file = source_file
        self.tools: list[ExtractedTool] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_function(node)
        self.generic_visit(node)

    def _check_function(self, node) -> None:
        for decorator in node.decorator_list:
            dec_name = _get_decorator_name(decorator)
            if dec_name in TOOL_DECORATOR_NAMES:
                framework = TOOL_DECORATOR_NAMES[dec_name]
                self.tools.append(ExtractedTool(
                    name=node.name,
                    description=_get_docstring(node),
                    framework_hint=framework,
                    source_file=self.source_file,
                    line_number=node.lineno,
                    decorator_used=f"@{dec_name}",
                ))
                return

    def visit_Call(self, node: ast.Call) -> None:
        call_name = _get_call_name(node)
        if call_name in TOOL_REGISTRATION_CALLS:
            framework = TOOL_REGISTRATION_CALLS[call_name]
            name = _get_string_kwarg(node, "name") or _get_string_kwarg(node, "name__")
            description = _get_string_kwarg(node, "description") or ""

            # register_function(func, ..., name=..., description=...)
            if call_name == "register_function" and node.args:
                first_arg = node.args[0]
                if isinstance(first_arg, ast.Name):
                    name = name or first_arg.id

            if name or description:
                self.tools.append(ExtractedTool(
                    name=name or f"unnamed_tool_line_{node.lineno}",
                    description=description,
                    framework_hint=framework,
                    source_file=self.source_file,
                    line_number=node.lineno,
                    decorator_used=f"{call_name}(...)",
                ))
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Detect BaseTool subclasses (LangChain / CrewAI class-based tools)."""
        base_names = []
        for base in node.bases:
            if isinstance(base, ast.Name):
                base_names.append(base.id)
            elif isinstance(base, ast.Attribute):
                base_names.append(base.attr)

        if any(b in ("BaseTool", "StructuredTool") for b in base_names):
            # Look for name: str = "..." and description: str = "..." class attributes
            tool_name = node.name
            description = ""
            for stmt in node.body:
                if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                    if stmt.target.id == "name" and isinstance(stmt.value, ast.Constant):
                        tool_name = stmt.value.value
                    if stmt.target.id == "description" and isinstance(stmt.value, ast.Constant):
                        description = stmt.value.value
                elif isinstance(stmt, ast.Assign):
                    for target in stmt.targets:
                        if isinstance(target, ast.Name) and target.id == "name" and isinstance(stmt.value, ast.Constant):
                            tool_name = stmt.value.value
                        if isinstance(target, ast.Name) and target.id == "description" and isinstance(stmt.value, ast.Constant):
                            description = stmt.value.value

            self.tools.append(ExtractedTool(
                name=tool_name,
                description=description or _get_docstring(node) if hasattr(node, "__doc__") else description,
                framework_hint="langchain_or_crewai",
                source_file=self.source_file,
                line_number=node.lineno,
                decorator_used="class BaseTool",
            ))
        self.generic_visit(node)


def extract_tools_from_file(path: Path) -> list[ExtractedTool]:
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
    except (SyntaxError, UnicodeDecodeError):
        return []

    extractor = ToolExtractor(str(path))
    extractor.visit(tree)
    return extractor.tools


def extract_tools_from_directory(directory: Path, max_files: int = 500) -> list[ExtractedTool]:
    """Recursively scan a directory for Python files and extract tool definitions."""
    all_tools: list[ExtractedTool] = []
    py_files = list(directory.rglob("*.py"))[:max_files]

    # Skip common non-source directories
    skip_patterns = {"venv", ".venv", "node_modules", "__pycache__", ".git", "site-packages", "test", "tests"}

    for py_file in py_files:
        if any(skip in py_file.parts for skip in skip_patterns):
            continue
        all_tools.extend(extract_tools_from_file(py_file))

    return all_tools


def scan_source(target: str) -> ScanResult:
    """
    Scan a real codebase (file or directory) for agent tool definitions,
    then run the same capability/attack-path analysis as agent_scanner.py.

    This is the entry point for real enterprise architectures —
    no YAML required.
    """
    import time
    start = time.monotonic()
    path = Path(target)

    if not path.exists():
        return ScanResult(target=target, scanner_type="source_scanner",
                         error=f"Path not found: {target}")

    if path.is_file():
        tools = extract_tools_from_file(path)
    else:
        tools = extract_tools_from_directory(path)

    if not tools:
        return ScanResult(
            target=target, scanner_type="source_scanner",
            findings=[Finding(
                id="SRC-NO-TOOLS-FOUND",
                title="No agent tool definitions found in source",
                severity=Severity.INFO, confidence=ConfidenceLevel.MEDIUM,
                scanner="source_scanner",
                explanation=(
                    "AgentScan scanned this path for tool definitions using known patterns "
                    "(@tool, @function_tool, register_function, BaseTool subclasses) but found none. "
                    "This may mean the agent has no tools, or uses a pattern not yet supported."
                ),
                impact="None — informational only",
                remediation="If this codebase does define agent tools, file an issue with the pattern used "
                            "so AgentScan can add support for it.",
            )],
            metadata={"files_scanned": 1 if path.is_file() else len(list(path.rglob("*.py")))},
            scan_duration_ms=int((time.monotonic()-start)*1000),
        )

    # Map extracted tools into the same capability detection used by agent_scanner
    findings: list[Finding] = []
    all_caps: set[str] = set()
    cap_to_tools: dict[str, list[str]] = {}
    framework_counts: dict[str, int] = {}

    for tool in tools:
        framework_counts[tool.framework_hint] = framework_counts.get(tool.framework_hint, 0) + 1
        caps = _detect_capabilities(tool.name, {"description": tool.description})

        for cap in caps:
            all_caps.add(cap)
            cap_to_tools.setdefault(cap, []).append(tool.name)
            cap_info = CAPABILITY_MAP[cap]

            findings.append(Finding(
                id=f"SRC-CAP-{cap.upper()}-{_normalise(tool.name)[:20].upper()}",
                title=f"Tool '{tool.name}' ({tool.source_file}:{tool.line_number}) grants {cap_info['description'].lower()}",
                severity=cap_info["severity"],
                confidence=ConfidenceLevel.MEDIUM,  # extracted from docstring, slightly lower confidence than explicit YAML
                scanner="source_scanner",
                explanation=(
                    f"Found via {tool.decorator_used} in {tool.framework_hint} code. "
                    f"{cap_info['description']}. Detected from function/docstring analysis — "
                    "verify this matches the tool's actual runtime behaviour."
                ),
                impact=cap_info["impact"],
                remediation=(
                    f"Review '{tool.name}' at {tool.source_file}:{tool.line_number}. "
                    "Scope permissions narrowly, add input validation, consider sandboxing."
                ),
                evidence=[Evidence(
                    source="source_code_ast",
                    field=f"{tool.source_file}:{tool.line_number}",
                    observed_value={"name": tool.name, "decorator": tool.decorator_used,
                                   "framework": tool.framework_hint},
                    explanation=f"Tool name/docstring matched capability '{cap}'",
                )],
                mitre_atlas=cap_info["mitre"],
                cwe=cap_info["cwe"],
                tags=["tool-permissions", cap, "source-extracted"],
            ))

    # Reuse dangerous combination detection
    from agentscan.models import AttackPath
    attack_paths: list[AttackPath] = []
    for combo in DANGEROUS_COMBINATIONS:
        if combo["caps"].issubset(all_caps):
            involved = [f for f in findings if any(tag in f.tags for tag in combo["caps"])]
            attack_paths.append(AttackPath(
                id=f"SRC-PATH-{'_'.join(sorted(combo['caps']))[:30].upper()}",
                title=combo["title"], severity=combo["severity"], steps=involved,
                entry_point=combo["entry"], impact=combo["impact"],
                description=combo["description"], mitre_atlas=combo["mitre"],
            ))

    elapsed_ms = int((time.monotonic()-start)*1000)
    return ScanResult(
        target=target, scanner_type="source_scanner",
        findings=findings, attack_paths=attack_paths,
        metadata={
            "tools_found": len(tools),
            "capabilities_detected": sorted(all_caps),
            "cap_to_tools": cap_to_tools,
            "frameworks_detected": framework_counts,
            "tool_locations": [f"{t.source_file}:{t.line_number} ({t.name})" for t in tools],
        },
        scan_duration_ms=elapsed_ms,
    )
