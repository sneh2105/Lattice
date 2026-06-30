#!/usr/bin/env python3
"""
AgentScan Evaluation Kit — automated benchmark runner.

Runs every scenario in vulnerable_agents/ and safe_agents/, checks the
output against the minimum thresholds documented in each scenario's
README, and reports pass/fail. This is what keeps the benchmark honest —
if a scenario's documented expectation drifts from actual scanner output,
this script catches it.

Usage:
    python run_benchmark.py
"""
from __future__ import annotations
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent

# (directory, command, min_risk_score, expect_attack_path, label)
SCENARIOS = [
    ("01_prompt_injection",     ["agentscan", "agent", "agent.yaml"],          50, True,  "Prompt injection -> shell"),
    ("02_secret_exfiltration",  ["agentscan", "agent", "agent.yaml"],          70, True,  "Secret exfiltration"),
    ("03_shell_execution",      ["agentscan", "source", "devops_agent.py"],    40, False, "Shell exec (source scan)"),
    ("04_database_exfiltration",["agentscan", "mcp", "mcp_server.json"],       60, True,  "Database exfil via MCP"),
    ("05_financial_fraud",      ["agentscan", "source", "finance_agent.py"],   55, True,  "Financial fraud chain"),
]

SAFE_SCENARIOS = [
    ("../safe_agents/01_scoped_search_agent", ["agentscan", "agent", "agent.yaml"], "Safe scoped search agent"),
]


def run_scan(directory: str, cmd: list[str]) -> dict:
    result = subprocess.run(
        cmd + ["--output", "json"],
        cwd=ROOT / directory,
        capture_output=True, text=True,
    )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        err = (result.stderr or result.stdout or "unknown error")[:200]
        return {"error": err}


def main():
    passed, failed = 0, 0

    print("\n  AgentScan Evaluation Kit — benchmark run\n")
    print(f"  {'Scenario':<32} {'Result':<10} {'Risk':<8} {'Paths':<8} {'Status'}")
    print(f"  {'-'*32} {'-'*10} {'-'*8} {'-'*8} {'-'*10}")

    for directory, cmd, min_risk, expect_path, label in SCENARIOS:
        data = run_scan(directory, cmd)
        if data.get("error"):
            print(f"  {label:<32} {'ERROR':<10} {'-':<8} {'-':<8} FAIL ({str(data['error'])[:40]})")
            failed += 1
            continue

        risk = data.get("risk_score", 0)
        n_paths = len(data.get("attack_paths", []))
        risk_ok = risk >= min_risk
        path_ok = (n_paths >= 1) if expect_path else True
        ok = risk_ok and path_ok

        status = "PASS" if ok else "FAIL"
        print(f"  {label:<32} {'vuln':<10} {risk:<8} {n_paths:<8} {status}")
        if ok: passed += 1
        else: failed += 1

    for directory, cmd, label in SAFE_SCENARIOS:
        data = run_scan(directory, cmd)
        risk = data.get("risk_score", 0)
        n_findings = data.get("summary", {}).get("total_findings", -1)
        ok = risk == 0 and n_findings == 0
        status = "PASS" if ok else "FAIL"
        print(f"  {label:<32} {'safe':<10} {risk:<8} {'-':<8} {status}")
        if ok: passed += 1
        else: failed += 1

    print(f"\n  {passed}/{passed+failed} scenarios passed\n")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
