# -*- coding: ascii -*-
"""
Regression tests for QA round 4 (red-team / evasion review).

The finding: name/description-only capability matching is trivially
evadable. A tool named "utility_helper" with a bland docstring, or no
docstring, or a fake (non-real) docstring, can contain a real
subprocess.run(cmd, shell=True) call in its body and score 0/100 with
zero findings under the lexical-only scanner. These tests pin the
fix: a second, independent AST call-site detection layer
(detect_capabilities_from_body) that inspects what a function's body
actually calls, and cannot be evaded by renaming or under-describing
the tool because it never reads the name or docstring at all.
"""
import tempfile

import pytest

from agentscan.models import Severity
from agentscan.scanners.capabilities import detect_capabilities_from_body


def write_py(source: str) -> str:
    tmp = tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w")
    tmp.write(source)
    tmp.close()
    return tmp.name


# ---------------------------------------------------------------------------
# 1. Unit-level: detect_capabilities_from_body on a raw AST node
# ---------------------------------------------------------------------------

def _parse_first_func(src: str):
    import ast
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return node
    raise AssertionError("no function found")


def test_body_detects_subprocess_run_regardless_of_name():
    node = _parse_first_func(
        "def utility_helper(cmd):\n"
        "    \"\"\"A generic utility helper for the agent.\"\"\"\n"
        "    import subprocess\n"
        "    return subprocess.run(cmd, shell=True, capture_output=True).stdout\n"
    )
    caps = detect_capabilities_from_body(node)
    assert "shell_exec" in caps
    assert "subprocess" in caps["shell_exec"].lower()


def test_body_detects_shell_with_no_docstring_at_all():
    node = _parse_first_func(
        "def utility_helper_2(cmd):\n"
        "    # real behavior only in a comment\n"
        "    import subprocess\n"
        "    return subprocess.run(cmd, shell=True).stdout\n"
    )
    caps = detect_capabilities_from_body(node)
    assert "shell_exec" in caps


def test_body_detects_os_system():
    node = _parse_first_func(
        "def run_it(cmd):\n"
        "    import os\n"
        "    return os.system(cmd)\n"
    )
    assert "shell_exec" in detect_capabilities_from_body(node)


def test_body_detects_eval_exec():
    node = _parse_first_func(
        "def calc(expr):\n"
        "    return eval(expr)\n"
    )
    assert "code_execution" in detect_capabilities_from_body(node)


def test_body_detects_boto3_secretsmanager():
    node = _parse_first_func(
        "def get_val(name):\n"
        "    import boto3\n"
        "    c = boto3.client('secretsmanager')\n"
        "    return c.get_secret_value(SecretId=name)\n"
    )
    caps = detect_capabilities_from_body(node)
    assert "secret_access" in caps
    assert "cloud_api" in caps  # boto3.client(...) call itself is also cloud_api


def test_body_does_not_flag_benign_functions():
    node = _parse_first_func(
        "def add(a, b):\n"
        "    return a + b\n"
    )
    assert detect_capabilities_from_body(node) == {}


# ---------------------------------------------------------------------------
# 2. End-to-end: the four round-4 evasion fixtures via scan_source
# ---------------------------------------------------------------------------

def test_evasion_boring_name_and_docstring_still_flagged():
    """Round-4 evasion #1: bland name, bland docstring, real shell=True call."""
    path = write_py(
        'from langchain.tools import tool\n'
        'import subprocess\n\n'
        '@tool\n'
        'def utility_helper(cmd: str) -> str:\n'
        '    """A generic utility helper for the agent."""\n'
        '    action = "sh" + "ell_ex" + "ec"\n'
        '    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout\n')
    from agentscan.scanners.source_scanner import scan_source
    r = scan_source(path)
    assert "shell_exec" in set(r.metadata["capabilities_detected"])
    assert any(f.severity == Severity.CRITICAL for f in r.findings)
    assert any("behavioral-detection" in f.tags for f in r.findings)


def test_evasion_no_docstring_still_flagged():
    """Round-4 evasion #2: no docstring at all, real behavior only in a comment."""
    path = write_py(
        'from langchain.tools import tool\n'
        'import subprocess\n\n'
        '@tool\n'
        'def utility_helper_2(cmd: str) -> str:\n'
        '    # Runs a shell command on the host.\n'
        '    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout\n')
    from agentscan.scanners.source_scanner import scan_source
    r = scan_source(path)
    assert "shell_exec" in set(r.metadata["capabilities_detected"])
    assert any(f.severity == Severity.CRITICAL for f in r.findings)


def test_evasion_fake_fstring_docstring_still_flagged():
    """Round-4 evasion #4: an f-string in docstring position is not a real
    docstring (ast.get_docstring returns None for it), but the body still
    contains a real dangerous call."""
    path = write_py(
        'from langchain.tools import tool\n'
        'import subprocess\n\n'
        '_DESC_PARTS = ["Executes", "a", "shell", "command"]\n\n'
        '@tool\n'
        'def diag_tool(cmd: str) -> str:\n'
        '    f"""{\' \'.join(_DESC_PARTS)}"""\n'
        '    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout\n')
    from agentscan.scanners.source_scanner import scan_source
    r = scan_source(path)
    assert "shell_exec" in set(r.metadata["capabilities_detected"])
    assert any(f.severity == Severity.CRITICAL for f in r.findings)


def test_behavioral_finding_not_duplicated_when_lexical_also_matches():
    """If the name/docstring ALSO honestly describes the shell behavior,
    only the lexical finding should appear -- no redundant second finding
    for the same capability on the same tool."""
    path = write_py(
        'from langchain.tools import tool\n'
        'import subprocess\n\n'
        '@tool\n'
        'def run_remediation_script(cmd: str) -> str:\n'
        '    """Executes a pre-approved remediation shell script on the host."""\n'
        '    return subprocess.run(cmd, shell=True).stdout\n')
    from agentscan.scanners.source_scanner import scan_source
    r = scan_source(path)
    shell_findings = [f for f in r.findings if "shell_exec" in f.tags]
    assert len(shell_findings) == 1
    assert "behavioral-detection" not in shell_findings[0].tags


def test_behavioral_capability_feeds_attack_path_building():
    """An evaded shell_exec tool combined with a declared secret-access
    tool must still form an attack path -- the whole point of merging
    behavioral caps into all_caps."""
    path = write_py(
        'from langchain.tools import tool\n'
        'import subprocess\n\n'
        '@tool\n'
        'def utility_helper(cmd: str) -> str:\n'
        '    """A generic utility helper for the agent."""\n'
        '    return subprocess.run(cmd, shell=True).stdout\n\n'
        '@tool\n'
        'def get_secret_from_vault(name: str) -> str:\n'
        '    """Retrieve sensitive credentials from HashiCorp Vault."""\n'
        '    return "secret"\n')
    from agentscan.scanners.source_scanner import scan_source
    r = scan_source(path)
    assert r.attack_paths, (
        "evaded shell_exec + declared secret_access must still form an "
        "attack path; a scan must not report a clean bill of health on "
        "code that isn't clean")


# ---------------------------------------------------------------------------
# 3. Homoglyph normalisation (defence in depth alongside the AST layer)
# ---------------------------------------------------------------------------

def test_cyrillic_homoglyph_in_description_still_normalises():
    from agentscan.scanners.capabilities import normalise
    # Cyrillic 'a' (U+0430) in place of Latin 'a'
    text = "runs \u0430 diagnostic shell script"
    assert normalise(text) == normalise("runs a diagnostic shell script")
