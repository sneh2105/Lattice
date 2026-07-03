# -*- coding: ascii -*-
"""
Regression tests for QA round 3.

The single most important finding of rounds 1-3: the capability keyword
taxonomy was duplicated across agent_scanner.py, mcp_scanner.py, and
mcp_scanner_v2.py, and fixes only ever landed in one copy at a time.
These tests pin (a) the canonical module's behaviour on every false
positive / false negative found across all three QA rounds, (b) that
every scanner actually routes through the canonical module, and (c) the
downstream fixes (Haystack attack paths, finding transparency,
compliance framework-name consistency).
"""
import inspect
import json
import tempfile
from pathlib import Path

import pytest

from agentscan.models import Severity
from agentscan.scanners.capabilities import (
    detect_capabilities,
    detect_capabilities_with_reasons,
)


def write_json(data: dict) -> str:
    tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w")
    json.dump(data, tmp)
    tmp.close()
    return tmp.name


def write_py(source: str) -> str:
    tmp = tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w")
    tmp.write(source)
    tmp.close()
    return tmp.name


# ---------------------------------------------------------------------------
# 1. Canonical detection: every FP/FN case from QA rounds 1-3
# ---------------------------------------------------------------------------

DETECTION_CASES = [
    # (name, description, must_have, must_not_have)
    # Round 2 regression fix: verb+target token co-occurrence
    ("run_remediation_script",
     "Executes a pre-approved remediation shell script on the affected host",
     {"shell_exec"}, set()),
    ("execute_patch_script",
     "Runs a patch deployment script on the server",
     {"shell_exec"}, set()),
    ("shell_diagnostic",
     "Diagnostic tool for host shell inspection",
     {"shell_exec"}, set()),
    # Round 1 P2a: bare "run" false positive -- and round 3 found the
    # same bug plus "repl"-in-"replica" alive in mcp_scanner_v2
    ("query_prod_db",
     "Run a read query against the production replica database",
     {"database"}, {"shell_exec", "code_execution"}),
    # Round 3: "shell"/"bash" satisfied both halves of the token pair
    ("detect_shell_companies",
     "Checks financial records to flag possible shell companies for AML "
     "compliance. Read-only lookup, no execution.",
     set(), {"shell_exec"}),
    # Round 3: run + "process" (a data-processing job, not an OS process)
    ("run_batch_process",
     "Runs a nightly batch data processing job in the analytics pipeline. "
     "No shell access.",
     set(), {"shell_exec"}),
    ("get_process_status",
     "Read-only lookup of a background job's status.",
     set(), {"shell_exec"}),
    # Round 1 P1c
    ("calculate_refund_estimate",
     "Calculates the estimated refund amount for a return",
     set(), {"financial_transaction"}),
    # Substring-in-word false positives of the same class, fixed in 0.2.1:
    # "cat" in "authentication" -> file_read
    ("fetch_aws_secret",
     "Retrieve a secret from AWS Secrets Manager for service authentication.",
     {"secret_access", "cloud_api"}, {"file_read"}),
    # "db" in "feedback" -> database
    ("collect_feedback",
     "Collects user feedback from the survey form",
     set(), {"database"}),
    # "ses" in "assesses" -> email_send
    ("assess_risk",
     "Assesses portfolio risk from market data",
     set(), {"email_send"}),
    # "cat" in "categorizes" -> file_read
    ("categorize_ticket",
     "Categorizes a support ticket by topic",
     set(), {"file_read"}),
    # "interpret" -> code_execution on an analytics tool
    ("interpret_results",
     "Interprets statistical analysis results for the report",
     set(), {"code_execution"}),
    # And the true positives those keywords exist for must still fire:
    ("python_repl", "Run python code in a REPL", {"code_execution"}, set()),
    ("exec_host_command", "Execute a command on the host", {"shell_exec"}, set()),
    ("read_file", "Read a file from disk", {"file_read"}, set()),
    ("send_email", "Send an email via SMTP", {"email_send"}, set()),
    ("db_query", "query the database", {"database"}, set()),
]


@pytest.mark.parametrize("name,desc,must,must_not", DETECTION_CASES,
                         ids=[c[0] for c in DETECTION_CASES])
def test_canonical_detection(name, desc, must, must_not):
    got = detect_capabilities(name, {"description": desc})
    missing = must - got
    extra = must_not & got
    assert not missing, f"{name}: missing expected capabilities {missing} (got {got})"
    assert not extra, f"{name}: false positive capabilities {extra} (got {got})"


def test_reasons_are_returned_for_every_capability():
    reasons = detect_capabilities_with_reasons(
        "run_remediation_script",
        {"description": "Executes a remediation shell script"})
    assert "shell_exec" in reasons
    # Token-based detections must explain WHICH tokens fired
    assert "token" in reasons["shell_exec"]


# ---------------------------------------------------------------------------
# 2. Single-source guard: no scanner may define its own keyword lists.
#    This is the structural fix for the root cause of rounds 1-3.
# ---------------------------------------------------------------------------

def test_no_scanner_defines_its_own_keyword_lists():
    from agentscan.scanners import (agent_scanner, source_scanner,
                                    mcp_scanner, mcp_scanner_v2)
    for module in (agent_scanner, source_scanner, mcp_scanner, mcp_scanner_v2):
        src = inspect.getsource(module)
        assert '"keywords"' not in src and "'keywords'" not in src, (
            f"{module.__name__} defines its own keyword list. All keyword "
            "matching must live in agentscan.scanners.capabilities -- "
            "duplicated taxonomies drift and re-introduce fixed bugs "
            "(QA rounds 1-3)."
        )


def test_all_four_scanners_agree_on_query_prod_db():
    """The round-3 bug: agent/source/mcp were fixed, graph-mcp (v2) was not."""
    tool = {"name": "query_prod_db",
            "description": "Run a read query against the production replica database"}

    # agent_scanner
    from agentscan.scanners.agent_scanner import scan_agent_config
    cfg = write_json({"tools": [tool]})
    r = scan_agent_config(cfg)
    assert not any("shell" in f.tags or "shell_exec" in f.tags for f in r.findings)
    assert not any("code_execution" in f.tags for f in r.findings)

    # source_scanner
    src = write_py(
        'from langchain.tools import tool\n\n'
        '@tool\n'
        'def query_prod_db(q: str) -> str:\n'
        '    """Run a read query against the production replica database."""\n'
        '    return "x"\n')
    from agentscan.scanners.source_scanner import scan_source
    r = scan_source(src)
    caps = set(r.metadata["capabilities_detected"])
    assert "shell_exec" not in caps and "code_execution" not in caps
    assert "database" in caps

    # mcp_scanner
    from agentscan.scanners.mcp_scanner import scan_mcp
    manifest = write_json({"tools": [dict(tool, inputSchema={"type": "object"})]})
    r = scan_mcp(manifest)
    assert not any("SHELL" in f.id or "CODE" in f.id for f in r.findings)

    # mcp_scanner_v2 (the copy round 3 caught un-fixed)
    from agentscan.scanners.mcp_scanner_v2 import scan_mcp_v2
    profile, _ = scan_mcp_v2(manifest)
    assert "shell_exec" not in profile.capabilities
    assert "code_execution" not in profile.capabilities
    assert "database" in profile.capabilities


def test_mcp_v2_still_detects_real_shell_and_gets_reason():
    from agentscan.scanners.mcp_scanner_v2 import scan_mcp_v2
    manifest = write_json({"tools": [
        {"name": "exec_host_command", "description": "Execute a command on the host",
         "inputSchema": {"type": "object"}},
    ]})
    profile, _ = scan_mcp_v2(manifest)
    assert "shell_exec" in profile.capabilities
    shell_findings = [f for t in profile.tools for f in t.findings
                      if "shell_exec" in f.tags]
    assert shell_findings
    assert any("because" in e.explanation for f in shell_findings
               for e in f.evidence)


# ---------------------------------------------------------------------------
# 3. Round-3 token-pair false positives, end-to-end through source scan
# ---------------------------------------------------------------------------

def test_shell_companies_and_batch_process_clean_via_source_scan():
    src = write_py(
        'from langchain.tools import tool\n\n'
        '@tool\n'
        'def detect_shell_companies(entity_name: str) -> str:\n'
        '    """Checks financial records to flag possible shell companies '
        'for AML compliance. Read-only lookup, no execution."""\n'
        '    return "stub"\n\n'
        '@tool\n'
        'def run_batch_process(job_id: str) -> str:\n'
        '    """Runs a nightly batch data processing job in the analytics '
        'pipeline. No shell access."""\n'
        '    return "stub"\n')
    from agentscan.scanners.source_scanner import scan_source
    r = scan_source(src)
    assert "shell_exec" not in set(r.metadata["capabilities_detected"]), (
        "AML/analytics tools must not be flagged as shell execution")


# ---------------------------------------------------------------------------
# 4. Haystack: risk 100 with zero attack paths (known issue, now fixed)
# ---------------------------------------------------------------------------

def test_shell_plus_secret_forms_attack_path():
    """shell_exec is itself an exfil channel; no network tool required."""
    from agentscan.scanners.agent_scanner import scan_agent_config
    cfg = write_json({"tools": [
        {"name": "run_shell", "description": "execute shell commands"},
        {"name": "get_secret_from_vault", "description": "read credentials from vault"},
    ]})
    r = scan_agent_config(cfg)
    assert r.attack_paths, "shell_exec + secret_access must form an attack path"
    assert any(p.severity == Severity.CRITICAL for p in r.attack_paths)


def test_haystack_fixture_produces_attack_paths():
    fixture = Path(__file__).resolve().parents[2] / "examples" / \
        "vulnerable_agents" / "11_haystack"
    if not fixture.exists():
        pytest.skip("examples not present")
    from agentscan.scanners.source_scanner import scan_source
    r = scan_source(str(fixture))
    assert len(r.attack_paths) >= 1, (
        "Haystack scenario has shell+vault+database tools; it must produce "
        "attack paths, not just a high risk score")


# ---------------------------------------------------------------------------
# 5. Compliance report: header framework names == detail framework names
# ---------------------------------------------------------------------------

def test_compliance_frameworks_covered_matches_control_citations():
    from agentscan.compliance.framework_mapper import (
        CONTROL_LIBRARY, map_findings_to_controls)
    from agentscan.scanners.agent_scanner import scan_agent_config
    cfg = write_json({"tools": [
        {"name": "run_shell", "description": "execute shell commands"},
        {"name": "http_fetch", "description": "make HTTP requests"},
    ]})
    result = scan_agent_config(cfg)
    report = map_findings_to_controls(result)
    covered = set(report.frameworks_covered)
    cited = {m["framework"] for entries in CONTROL_LIBRARY.values()
             for m in entries}
    # Every framework cited anywhere in the control library must appear in
    # the header list, and vice versa -- an audit artifact must be
    # internally consistent.
    assert covered == cited
