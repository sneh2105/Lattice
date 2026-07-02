# -*- coding: utf-8 -*-
"""
agentscan demo / agentscan benchmark
======================================
Zero-setup evaluation: run AgentScan against bundled, intentionally
vulnerable agents (plus a safe baseline) without needing any of your own
code. Answers "does this actually work?" in one command.

`agentscan demo`      -- human-readable, narrated walkthrough (first impression)
`agentscan benchmark` -- pass/fail table against documented thresholds (CI-style)

Both operate on the same fixtures in examples/vulnerable_agents/ and
examples/safe_agents/, located relative to the installed package so this
works regardless of the user's current directory.
"""
import agentscan._compat  # force UTF-8 before any print -- Windows fix
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from agentscan._compat import (
    SYM_OK, SYM_FAIL, SYM_WARN, SYM_ARROW, SYM_BLOCK_FULL, SYM_BLOCK_EMPTY
)


def _find_examples_root():
    """
    Locate examples/vulnerable_agents relative to this installed package.
    Works whether installed via `pip install -e .` (repo layout) or as a
    built wheel that bundled the examples directory.
    """
    here = Path(__file__).resolve()
    candidates = [
        here.parent.parent / "examples",
        here.parent / "examples",
        Path.cwd() / "examples",
    ]
    for c in candidates:
        if (c / "vulnerable_agents").exists():
            return c
    return None


@dataclass
class ScenarioSpec:
    directory: str
    cmd: list
    min_risk: int
    expect_path: bool
    label: str
    narrative: str


SCENARIOS = [
    ScenarioSpec("vulnerable_agents/01_prompt_injection", ["agent", "agent.yaml"],
                 50, True, "Prompt injection -> shell",
                 "An agent with browser + shell tools -- a malicious web page can hijack it into running commands"),
    ScenarioSpec("vulnerable_agents/02_secret_exfiltration", ["agent", "agent.yaml"],
                 70, True, "Secret exfiltration",
                 "An agent that can read AWS secrets AND make network calls -- a complete exfil path"),
    ScenarioSpec("vulnerable_agents/03_shell_execution", ["source", "devops_agent.py"],
                 40, False, "Shell exec (real source code)",
                 "Real LangChain Python code (no YAML) with a subprocess.run() call"),
    ScenarioSpec("vulnerable_agents/04_database_exfiltration", ["mcp", "mcp_server.json"],
                 40, True, "Database exfil via MCP",
                 "An MCP server with DB + network tools and no authentication configured"),
    ScenarioSpec("vulnerable_agents/05_financial_fraud", ["source", "finance_agent.py"],
                 55, True, "Financial fraud chain",
                 "An agent that can look up account data AND initiate wire transfers"),
    ScenarioSpec("vulnerable_agents/06_nova_act_credential_exfil", ["source", "nova_act_agent.py"],
                 90, True, "Amazon Nova Act credential + shell",
                 "A Nova Act browser automation workflow with AWS credential and shell diagnostic tools"),
    ScenarioSpec("vulnerable_agents/07_custom_inhouse_agent", ["source", "internal_agent.py"],
                 90, True, "Custom in-house agent (no framework)",
                 "A hand-built agent using raw Anthropic/OpenAI tool schemas -- no LangChain, CrewAI, or any named SDK"),
    ScenarioSpec("vulnerable_agents/08_nocode_dify_export", ["agent", "dify_export.yml"],
                 90, False, "No-code platform export (Dify-style)",
                 "A visual workflow builder export -- no source code, tools nested under model_config.agent_mode"),
    ScenarioSpec("vulnerable_agents/09_pydantic_ai_llamaindex", ["source", "llamaindex_agent.py"],
                 90, True, "PydanticAI + LlamaIndex",
                 "LlamaIndex FunctionTool.from_defaults() registering a secret-access and shell-exec tool"),
    ScenarioSpec("vulnerable_agents/10_n8n_flowise_nocode", ["agent", "n8n_workflow.json"],
                 90, True, "n8n workflow (no-code)",
                 "n8n AI Agent node export with shell, database, and credential tools"),
    ScenarioSpec("vulnerable_agents/11_haystack", ["source", "haystack_agent.py"],
                 90, False, "Haystack agent",
                 "Haystack Tool() registration pattern with shell, database, and vault tools"),
]

SAFE_SCENARIO = ScenarioSpec(
    "safe_agents/01_scoped_search_agent", ["agent", "agent.yaml"],
    0, False, "Safe scoped search agent",
    "A well-scoped, read-only agent -- should produce zero findings"
)


def _run_scan(examples_root, spec):
    target_dir = examples_root / spec.directory
    result = subprocess.run(
        ["agentscan"] + spec.cmd + ["--output", "json"],
        cwd=target_dir, capture_output=True, text=True, encoding="utf-8",
    )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        err = (result.stderr or result.stdout or "unknown error")[:200]
        return {"error": err}


def run_demo():
    """Narrated, human-readable walkthrough. Returns exit code."""
    RED    = "\033[91m"
    ORANGE = "\033[33m"
    GREEN  = "\033[92m"
    DIM    = "\033[2m"
    BOLD   = "\033[1m"
    CYAN   = "\033[96m"
    RESET  = "\033[0m"
    use_colour = sys.stdout.isatty()

    def c(code, s):
        if use_colour:
            return code + s + RESET
        return s

    examples_root = _find_examples_root()
    if not examples_root:
        print(c(RED, "  Could not locate bundled examples/ directory."))
        print(c(DIM, "  Try running from the repo root, or check your installation."))
        return 1

    n = len(SCENARIOS)
    print("")
    print(c(BOLD + CYAN, "  AgentScan Demo") + " -- zero-setup evaluation")
    print("")
    print(c(DIM, "  Running " + str(n) + " intentionally vulnerable agents + 1 safe baseline..."))
    print("")

    all_ok = True
    for spec in SCENARIOS:
        print(c(BOLD, "  " + spec.label))
        print(c(DIM, "  " + spec.narrative))
        data = _run_scan(examples_root, spec)
        if data.get("error"):
            err_msg = SYM_FAIL + " ERROR: " + str(data["error"])[:80]
            print("  " + c(RED, err_msg))
            print("")
            all_ok = False
            continue
        risk = data.get("risk_score", 0)
        n_paths = len(data.get("attack_paths", []))
        ok = risk >= spec.min_risk and (n_paths >= 1 if spec.expect_path else True)
        rc = RED if risk >= 70 else ORANGE if risk >= 40 else GREEN
        icon = c(GREEN, SYM_OK) if ok else c(RED, SYM_FAIL)
        risk_str = "Risk " + c(rc, str(risk) + "/100")
        print("  " + icon + " " + risk_str + "  -  " + str(n_paths) + " attack path(s) found")
        if data.get("attack_paths"):
            title = data["attack_paths"][0]["title"]
            print("    " + c(DIM, title))
        print("")
        if not ok:
            all_ok = False

    # Safe baseline
    print(c(BOLD, "  " + SAFE_SCENARIO.label))
    print(c(DIM, "  " + SAFE_SCENARIO.narrative))
    data = _run_scan(examples_root, SAFE_SCENARIO)
    risk = data.get("risk_score", -1)
    n_findings = data.get("summary", {}).get("total_findings", -1)
    safe_ok = risk == 0 and n_findings == 0
    icon = c(GREEN, SYM_OK) if safe_ok else c(RED, SYM_FAIL)
    note = "no false positives" if safe_ok else "UNEXPECTED FINDINGS"
    risk_display = c(GREEN, "0/100") if safe_ok else c(RED, str(risk) + "/100")
    print("  " + icon + " Risk " + risk_display + "  -  " + str(n_findings) + " finding(s) -- " + note)
    print("")
    if not safe_ok:
        all_ok = False

    if all_ok:
        msg = SYM_OK + " AgentScan correctly identified all " + str(len(SCENARIOS)) + " attack patterns with zero false positives."
        print("  " + c(GREEN + BOLD, msg))
    else:
        msg = SYM_FAIL + " Some scenarios did not match expected output -- see above."
        print("  " + c(RED + BOLD, msg))

    print("")
    print(c(DIM, "  Try it on your own code: agentscan doctor . && agentscan source ."))
    print("")

    return 0 if all_ok else 1


def run_benchmark():
    """Compact pass/fail table. Returns exit code (0 = all pass)."""
    examples_root = _find_examples_root()
    if not examples_root:
        print("Could not locate bundled examples/ directory.", file=sys.stderr)
        return 1

    passed, failed = 0, 0
    print("")
    print("  AgentScan Benchmark")
    print("")
    label_w = 36
    col_header = "  " + "Scenario".ljust(label_w) + " " + "Risk".ljust(8) + " " + "Paths".ljust(8) + " " + "Status"
    print(col_header)
    print("  " + "-" * label_w + " " + "-" * 8 + " " + "-" * 8 + " " + "-" * 10)

    for spec in SCENARIOS:
        data = _run_scan(examples_root, spec)
        if data.get("error"):
            row = "  " + spec.label[:label_w].ljust(label_w) + " " + "-".ljust(8) + " " + "-".ljust(8) + " FAIL"
            print(row)
            failed += 1
            continue
        risk = data.get("risk_score", 0)
        n_paths = len(data.get("attack_paths", []))
        ok = risk >= spec.min_risk and (n_paths >= 1 if spec.expect_path else True)
        status = "PASS" if ok else "FAIL"
        row = "  " + spec.label[:label_w].ljust(label_w) + " " + str(risk).ljust(8) + " " + str(n_paths).ljust(8) + " " + status
        print(row)
        if ok:
            passed += 1
        else:
            failed += 1

    data = _run_scan(examples_root, SAFE_SCENARIO)
    risk = data.get("risk_score", -1)
    n_findings = data.get("summary", {}).get("total_findings", -1)
    safe_ok = risk == 0 and n_findings == 0
    status = "PASS" if safe_ok else "FAIL"
    row = "  " + SAFE_SCENARIO.label[:label_w].ljust(label_w) + " " + str(risk).ljust(8) + " " + "-".ljust(8) + " " + status
    print(row)
    if safe_ok:
        passed += 1
    else:
        failed += 1

    total = passed + failed
    print("")
    print("  " + str(passed) + "/" + str(total) + " scenarios passed")
    print("")
    return 0 if failed == 0 else 1
