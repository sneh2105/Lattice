# -*- coding: utf-8 -*-
"""
Source Code Scanner
=====================
Real enterprises don't have YAML configs describing their agents -- they have
Python source code with framework-specific tool definitions. This scanner
parses that source directly via AST, with zero execution of the code.

Supported patterns (auto-detected):
  LangChain  -- @tool decorator, Tool(name=..., func=...), BaseTool subclasses
  CrewAI     -- BaseTool subclasses, @tool decorator
  AutoGen    -- @register_function, function passed to register_function()
  OpenAI SDK -- @function_tool decorator
  Amazon Nova Act -- @tool decorator (same convention as LangChain/CrewAI)
  Custom / no framework -- raw Anthropic or OpenAI native tool schemas:
                          TOOLS = [{"name": ..., "description": ..., "input_schema": {...}}]
                          This is the format companies use when they build their own
                          orchestration layer directly on the model provider's API,
                          which is common at larger enterprises that haven't adopted
                          a third-party agent framework.
  Generic    -- any function with a docstring passed into a tools=[...] list

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
from agentscan.scanners.capabilities import (
    CAPABILITY_MAP,
    DANGEROUS_COMBINATIONS,
    detect_capabilities_with_reasons as _detect_capabilities_with_reasons,
    detect_capabilities_from_body,
    collect_import_aliases,
    normalise as _normalise,
)


@dataclass
class ExtractedTool:
    name: str
    description: str
    framework_hint: str       # "langchain" | "crewai" | "autogen" | "openai_agents" | "unknown"
    source_file: str
    line_number: int
    decorator_used: str = ""
    # AST call-site evidence (subprocess.run, eval, boto3.client, ...)
    # found by walking the function's real body, independent of what
    # its name/docstring claim. See capabilities.detect_capabilities_from_body.
    body_capabilities: dict = None  # type: dict[str, str], set post-init below

    def __post_init__(self):
        if self.body_capabilities is None:
            self.body_capabilities = {}


# Decorator / call patterns that mark a function as an agent tool
TOOL_DECORATOR_NAMES = {
    "tool": "langchain_crewai_nova_act_or_pydantic_ai",  # @tool / @agent.tool -- LangChain, CrewAI, Nova Act, PydanticAI all use this name
    "tool_plain": "pydantic_ai",             # @agent.tool_plain (PydanticAI -- synchronous tools without RunContext)
    "function_tool": "openai_agents",       # @function_tool (OpenAI Agents SDK)
    "kernel_function": "semantic_kernel",   # @sk.kernel_function (Semantic Kernel)
}

# Function calls that register a tool (not decorator-based)
TOOL_REGISTRATION_CALLS = {
    "register_function": "autogen",
    "Tool": "langchain_or_haystack",   # Tool(name=..., func=...) -- LangChain and Haystack both use this
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
        self._function_docstrings: dict[str, str] = {}
        # name -> FunctionDef/AsyncFunctionDef node, populated in a pre-pass.
        # Used to resolve the real function body for registration-style
        # tools (register_function(my_func), Tool(func=my_func), ...)
        # so behavioral (AST) detection applies to them too, not just
        # decorator-based tools.
        self._function_nodes: dict[str, object] = {}
        # Import-alias tables populated in extract_tools_from_file's
        # pre-pass, used to resolve aliased/indirect dangerous calls
        # before AST body matching (see capabilities.collect_import_aliases).
        self._module_aliases: dict[str, str] = {}
        self._func_aliases: dict[str, str] = {}
        # Base classes that mark a class as an agent tool.
        # Seeded with known third-party names; grows as we find internal wrappers.
        self._known_tool_bases: set[str] = {
            "BaseTool", "StructuredTool",  # LangChain / CrewAI
        }

    def _body_caps(self, node) -> dict:
        """Convenience wrapper: AST body detection with this file's
        alias tables and local-function resolver wired in."""
        return detect_capabilities_from_body(
            node,
            module_aliases=self._module_aliases,
            func_aliases=self._func_aliases,
            resolve_local_call=self._function_nodes.get,
        )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function_docstrings[node.name] = _get_docstring(node)
        self._check_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function_docstrings[node.name] = _get_docstring(node)
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
                    body_capabilities=self._body_caps(node),
                ))
                return

    def visit_Call(self, node: ast.Call) -> None:
        call_name = _get_call_name(node)

        # LlamaIndex pattern: FunctionTool.from_defaults(my_function, ...)
        # call_name is "from_defaults" (the method), base is "FunctionTool" (the class)
        if call_name == "from_defaults" and isinstance(node.func, ast.Attribute) \
           and isinstance(node.func.value, ast.Name) and node.func.value.id == "FunctionTool":
            name = _get_string_kwarg(node, "name")
            description = _get_string_kwarg(node, "description") or ""
            real_docstring = ""
            resolved_node = None
            if node.args:
                first_arg = node.args[0]
                if isinstance(first_arg, ast.Name):
                    name = name or first_arg.id
                    real_docstring = self._function_docstrings.get(first_arg.id, "")
                    resolved_node = self._function_nodes.get(first_arg.id)
            combined_description = " ".join(filter(None, [description, real_docstring]))
            if name or combined_description:
                self.tools.append(ExtractedTool(
                    name=name or f"unnamed_tool_line_{node.lineno}",
                    description=combined_description,
                    framework_hint="llamaindex",
                    source_file=self.source_file,
                    line_number=node.lineno,
                    decorator_used="FunctionTool.from_defaults(...)",
                    body_capabilities=(self._body_caps(resolved_node)
                                       if resolved_node is not None else {}),
                ))
            self.generic_visit(node)
            return

        if call_name in TOOL_REGISTRATION_CALLS:
            framework = TOOL_REGISTRATION_CALLS[call_name]
            name = _get_string_kwarg(node, "name") or _get_string_kwarg(node, "name__")
            description = _get_string_kwarg(node, "description") or ""

            # register_function(func, ..., name=..., description=...)
            # The description kwarg is often a vague LLM-facing summary --
            # the function's own docstring usually contains the real behaviour detail.
            real_docstring = ""
            resolved_node = None
            if call_name == "register_function" and node.args:
                first_arg = node.args[0]
                if isinstance(first_arg, ast.Name):
                    name = name or first_arg.id
                    real_docstring = self._function_docstrings.get(first_arg.id, "")
                    resolved_node = self._function_nodes.get(first_arg.id)

            # Tool(name=..., func=my_function, ...) / Tool(name=..., function=my_function, ...)
            if resolved_node is None:
                for kw in node.keywords:
                    if kw.arg in ("func", "function") and isinstance(kw.value, ast.Name):
                        resolved_node = self._function_nodes.get(kw.value.id)
                        break

            combined_description = " ".join(filter(None, [description, real_docstring]))

            if name or combined_description:
                self.tools.append(ExtractedTool(
                    name=name or f"unnamed_tool_line_{node.lineno}",
                    description=combined_description,
                    framework_hint=framework,
                    source_file=self.source_file,
                    line_number=node.lineno,
                    decorator_used=f"{call_name}(...)",
                    body_capabilities=(self._body_caps(resolved_node)
                                       if resolved_node is not None else {}),
                ))
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """
        Detect BaseTool subclasses (LangChain / CrewAI class-based tools).

        Handles one level of internal wrapper inheritance -- the common enterprise
        pattern where every team subclasses a shared internal base class
        (e.g. InternalAPITool(BaseTool)) rather than inheriting from the
        third-party base directly. We build a set of known tool base classes
        as we walk the AST, so InternalAPITool gets added to the set when we
        see it subclasses BaseTool, and LookupAccountBalanceTool(InternalAPITool)
        is then correctly recognised as a tool on the next pass.
        """
        base_names = []
        for base in node.bases:
            if isinstance(base, ast.Name):
                base_names.append(base.id)
            elif isinstance(base, ast.Attribute):
                base_names.append(base.attr)

        # Direct match OR one-level-deep internal wrapper
        is_tool_class = any(b in self._known_tool_bases for b in base_names)

        if is_tool_class:
            # Check if this is itself a wrapper (no name/description attrs = abstract base)
            has_name_attr = False
            has_desc_attr = False
            tool_name = node.name
            description = ""

            for stmt in node.body:
                if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                    if stmt.target.id == "name" and isinstance(stmt.value, ast.Constant):
                        tool_name = stmt.value.value
                        has_name_attr = True
                    if stmt.target.id == "description" and isinstance(stmt.value, ast.Constant):
                        description = stmt.value.value
                        has_desc_attr = True
                elif isinstance(stmt, ast.Assign):
                    for target in stmt.targets:
                        if isinstance(target, ast.Name) and target.id == "name" and isinstance(stmt.value, ast.Constant):
                            tool_name = stmt.value.value
                            has_name_attr = True
                        if isinstance(target, ast.Name) and target.id == "description" and isinstance(stmt.value, ast.Constant):
                            description = stmt.value.value
                            has_desc_attr = True

            if has_name_attr or has_desc_attr:
                # Concrete tool class -- extract it
                self.tools.append(ExtractedTool(
                    name=tool_name,
                    description=description,
                    framework_hint="langchain_crewai_or_nova_act",
                    source_file=self.source_file,
                    line_number=node.lineno,
                    decorator_used="class BaseTool",
                ))
            else:
                # Abstract wrapper class -- add its name to known bases so
                # subclasses of it are detected too (one-level indirection)
                self._known_tool_bases.add(node.name)

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """
        Detect raw Anthropic/OpenAI-native tool schemas -- the pattern used by
        companies running a custom in-house agent with no named framework:

            TOOLS = [
                {"name": "...", "description": "...", "input_schema": {...}},
                ...
            ]

        This is the single most common pattern for in-house orchestration
        layers, since it's literally the wire format both Anthropic's and
        OpenAI's APIs expect -- no SDK wrapper required.
        """
        if not isinstance(node.value, ast.List):
            self.generic_visit(node)
            return

        for element in node.value.elts:
            if not isinstance(element, ast.Dict):
                continue
            entry = self._dict_literal_to_pydict(element)
            if not entry:
                continue
            # Require both name and description to avoid matching unrelated list-of-dict data
            name = entry.get("name")
            description = entry.get("description", "")
            if not isinstance(name, str):
                continue
            # Require at least one more tool-schema-shaped key to reduce false positives
            # on generic config dicts that happen to have name/description fields
            schema_markers = {"input_schema", "inputSchema", "parameters", "function"}
            if not (schema_markers & set(entry.keys())):
                continue

            self.tools.append(ExtractedTool(
                name=name,
                description=str(description) if description else "",
                framework_hint="raw_api_tool_schema",
                source_file=self.source_file,
                line_number=element.lineno,
                decorator_used="native tool schema (Anthropic/OpenAI API format)",
            ))
        self.generic_visit(node)

    @staticmethod
    def _dict_literal_to_pydict(node: ast.Dict) -> dict | None:
        """Best-effort: convert a simple AST dict literal (string/constant values only) to a Python dict."""
        result: dict = {}
        for key_node, val_node in zip(node.keys, node.values):
            if not isinstance(key_node, ast.Constant) or not isinstance(key_node.value, str):
                continue
            key = key_node.value
            if isinstance(val_node, ast.Constant):
                result[key] = val_node.value
            elif isinstance(val_node, (ast.Dict, ast.List)):
                # Nested structures (e.g. input_schema) -- just mark presence, don't recurse
                result[key] = {}
            else:
                result[key] = None
        return result or None


# Base class names that mark a class as an agent tool (canonical names from third-party libs)
_KNOWN_THIRD_PARTY_BASES = {"BaseTool", "StructuredTool"}


def extract_tools_from_file(path: Path) -> list[ExtractedTool]:
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
    except (SyntaxError, UnicodeDecodeError):
        return []

    extractor = ToolExtractor(str(path))

    # Pre-pass 0: collect import aliases for known base classes
    # e.g. "from crewai_tools import BaseTool as CrewBaseTool" -- add "CrewBaseTool"
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            aliases = node.names if hasattr(node, "names") else []
            for alias in aliases:
                # alias.name is the original name, alias.asname is the local alias
                if alias.name in _KNOWN_THIRD_PARTY_BASES and alias.asname:
                    extractor._known_tool_bases.add(alias.asname)
                # Also add without alias (in case it's a direct import)
                if alias.name in _KNOWN_THIRD_PARTY_BASES:
                    extractor._known_tool_bases.add(alias.name)

    # Pre-pass 1: collect all function docstrings regardless of source order
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            extractor._function_docstrings[node.name] = _get_docstring(node)
            extractor._function_nodes[node.name] = node

    # Pre-pass: import alias resolution for behavioral (AST) detection --
    # see capabilities.collect_import_aliases for why this exists.
    extractor._module_aliases, extractor._func_aliases = collect_import_aliases(tree)

    # Pre-pass 2: collect wrapper/abstract base classes (internal BaseTool subclasses
    # with no name/description attributes -- they are wrappers, not concrete tools).
    # We do this as a separate walk so the bases set is complete before Pass 3.
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        base_names = []
        for base in node.bases:
            if isinstance(base, ast.Name):
                base_names.append(base.id)
            elif isinstance(base, ast.Attribute):
                base_names.append(base.attr)
        if not any(b in extractor._known_tool_bases for b in base_names):
            continue
        # Check if it has name/description attrs (concrete tool) or not (wrapper)
        has_tool_attrs = any(
            (isinstance(s, ast.AnnAssign) and isinstance(s.target, ast.Name)
             and s.target.id in ("name", "description") and isinstance(s.value, ast.Constant))
            or (isinstance(s, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id in ("name", "description")
                        for t in s.targets)
                and isinstance(s.value, ast.Constant))
            for s in node.body
        )
        if not has_tool_attrs:
            # Abstract wrapper -- add its name so subclasses are detected
            extractor._known_tool_bases.add(node.name)

    # Pass 3: extract tools (decorators, classes, registration calls)
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

    This is the entry point for real enterprise architectures --
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
        # Check if the file(s) actually import any agent frameworks.
        # If they do, we found something we couldn't parse -- that's different
        # from a clean codebase with no agents. Warn so reviewers don't trust
        # a false green.
        framework_imports_found = []
        check_content = ""
        if path.is_file():
            try:
                check_content = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                pass
        else:
            for py_file in list(path.rglob("*.py"))[:50]:
                try:
                    check_content += py_file.read_text(encoding="utf-8", errors="ignore")[:2000]
                except Exception:
                    pass

        import re as _re
        FRAMEWORK_HINTS = {
            "LangChain / CrewAI / Nova Act": [r"from langchain", r"from crewai", r"from nova_act"],
            "AutoGen": [r"import autogen", r"register_function"],
            "OpenAI Agents SDK": [r"from openai_agents", r"function_tool"],
        "OpenAI (raw client)": [r"from openai import", r"import openai"],
        "Anthropic (raw client)": [r"from anthropic import", r"import anthropic"],
            "LlamaIndex": [r"from llama_index"],
            "PydanticAI": [r"from pydantic_ai"],
            "Haystack": [r"from haystack"],
        }
        for framework, patterns in FRAMEWORK_HINTS.items():
            if any(_re.search(p, check_content) for p in patterns):
                framework_imports_found.append(framework)

        if framework_imports_found:
            title = "Agent framework imported but zero tools detected -- coverage gap"
            explanation = (
                "AgentScan found imports from " + ", ".join(framework_imports_found) +
                " but could not extract any tool definitions using known static patterns "
                "(@tool, @function_tool, register_function, BaseTool subclasses, "
                "FunctionTool.from_defaults, raw schema dicts). "
                "This typically means tools are registered dynamically (via a registry dict, "
                "factory function, or internal wrapper class) -- a pattern AgentScan cannot "
                "fully resolve without runtime information. "
                "This is NOT a clean result -- it means the scan could not assess coverage."
            )
            remediation = (
                "Manually review tool registration in this codebase. "
                "If tools are registered via a dict or factory, consider adding a static "
                "TOOLS = [...] declaration that AgentScan can read. "
                "File an issue with the pattern so support can be added."
            )
            severity = Severity.MEDIUM
        else:
            title = "No agent tool definitions found in source"
            explanation = (
                "AgentScan scanned this path for tool definitions using known patterns "
                "(@tool, @function_tool, register_function, BaseTool subclasses) but found none. "
                "This may mean the agent has no tools, or uses a pattern not yet supported."
            )
            remediation = (
                "If this codebase does define agent tools, file an issue with the pattern used "
                "so AgentScan can add support for it."
            )
            severity = Severity.INFO

        return ScanResult(
            target=target, scanner_type="source_scanner",
            findings=[Finding(
                id="SRC-NO-TOOLS-FOUND",
                title=title,
                severity=severity, confidence=ConfidenceLevel.MEDIUM,
                scanner="source_scanner",
                explanation=explanation,
                impact="None -- informational only" if severity == Severity.INFO else
                       "Tools may exist that AgentScan could not assess -- treat as unknown risk.",
                remediation=remediation,
            )],
            metadata={
                "files_scanned": 1 if path.is_file() else len(list(path.rglob("*.py"))),
                "framework_imports_found": framework_imports_found,
            },
            scan_duration_ms=int((time.monotonic()-start)*1000),
        )

    # Map extracted tools into the same capability detection used by agent_scanner
    findings: list[Finding] = []
    all_caps: set[str] = set()
    cap_to_tools: dict[str, list[str]] = {}
    framework_counts: dict[str, int] = {}

    for tool in tools:
        framework_counts[tool.framework_hint] = framework_counts.get(tool.framework_hint, 0) + 1
        cap_reasons = _detect_capabilities_with_reasons(tool.name, {"description": tool.description})
        caps = set(cap_reasons)

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
                    f"{cap_info['description']}. Detected from function/docstring analysis -- "
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
                    explanation=f"Capability '{cap}' assigned because: {cap_reasons[cap]}",
                )],
                mitre_atlas=cap_info["mitre"],
                cwe=cap_info["cwe"],
                tags=["tool-permissions", cap, "source-extracted"],
            ))

        # Behavioral (AST call-site) layer -- independent of name/docstring.
        # Round-4 red-team finding: name/docstring-only matching is
        # evadable (boring name, missing docstring, or a non-docstring
        # f-string all defeat the lexical layer above while the function
        # still contains a real subprocess.run(..., shell=True) call).
        # This layer inspects the actual function body and cannot be
        # evaded the same way. Its capabilities are merged into all_caps
        # / cap_to_tools so attack-path building still sees them even
        # when the lexical layer found nothing for this tool -- a scan
        # must not report a clean bill of health on code that isn't clean.
        for cap, reason in tool.body_capabilities.items():
            all_caps.add(cap)
            cap_to_tools.setdefault(cap, []).append(tool.name)
            if cap in caps:
                # Lexical layer already found and reported this capability
                # for this tool; the behavioral signal corroborates it,
                # no need for a second finding.
                continue
            cap_info = CAPABILITY_MAP[cap]
            findings.append(Finding(
                id=f"SRC-BEHAV-{cap.upper()}-{_normalise(tool.name)[:20].upper()}",
                title=(
                    f"Tool '{tool.name}' ({tool.source_file}:{tool.line_number}) "
                    f"{cap_info['description'].lower()} -- undeclared in name/description"
                ),
                severity=cap_info["severity"],
                confidence=ConfidenceLevel.HIGH,  # direct AST evidence of a real call, not a lexical guess
                scanner="source_scanner",
                explanation=(
                    f"Behavioral detection: this tool's name and description do not mention "
                    f"'{cap}', but its function body contains {reason.replace('AST evidence: ', '')}. "
                    f"{cap_info['description']}. This mismatch between declared and actual "
                    "behavior may indicate under-documentation, or an attempt to evade "
                    "name/description-based review -- verify manually."
                ),
                impact=cap_info["impact"],
                remediation=(
                    f"Review '{tool.name}' at {tool.source_file}:{tool.line_number}. "
                    "Its name/description should accurately reflect that it can "
                    f"{cap_info['description'].lower()}. Scope permissions narrowly, "
                    "add input validation, consider sandboxing."
                ),
                evidence=[Evidence(
                    source="source_code_ast_body",
                    field=f"{tool.source_file}:{tool.line_number}",
                    observed_value={"name": tool.name, "framework": tool.framework_hint},
                    explanation=reason,
                )],
                mitre_atlas=cap_info["mitre"],
                cwe=cap_info["cwe"],
                tags=["tool-permissions", cap, "source-extracted", "behavioral-detection",
                      "name-description-mismatch"],
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
