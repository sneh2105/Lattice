# -*- coding: utf-8 -*-
"""AgentScan CLI v0.3.0"""
from __future__ import annotations
import agentscan._compat   # force UTF-8 stdout/stderr before any output -- Windows fix
import argparse, sys
from pathlib import Path

from agentscan.scanners.agent_scanner import scan_agent_config
from agentscan.scanners.source_scanner import scan_source
from agentscan.scanners.mcp_scanner import scan_mcp
from agentscan.scanners.supply_chain_scanner import scan_supply_chain
from agentscan.outputs.terminal import render_result
from agentscan.outputs.json_output import to_json, to_sarif
from agentscan.outputs.html_report import generate_html_report
from agentscan.models import Severity
from agentscan._fileutil import atomic_write_text
from agentscan.cli_compliance import add_compliance_parser, cmd_map, cmd_dpia, cmd_audit
from agentscan.graph.cli_graph import (add_graph_parser, cmd_graph_agent, cmd_graph_mcp, cmd_graph_chain,
                                        cmd_graph_trustflow, cmd_graph_escalation, cmd_graph_query)
from agentscan.runtime.cli_runtime import (add_runtime_parser, cmd_runtime_analyse, cmd_prompt_flow,
                                            cmd_identity, cmd_goal_integrity)
from agentscan.doctor import run_doctor, render_doctor_report
from agentscan.benchmark import run_demo, run_benchmark


def _output(result, fmt, verbose):
    if fmt == "json":   return to_json(result)
    if fmt == "sarif":  return to_sarif(result)
    return render_result(result, verbose=verbose)

def _is_html(fmt):
    return fmt == "html"

def _should_fail(result, fail_on):
    if not fail_on: return False
    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
    idx = order.index(Severity(fail_on.upper()))
    return any(order.index(f.severity) <= idx for f in result.reportable_findings if f.severity in order)

def main():
    parser = argparse.ArgumentParser(prog="agentscan",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Scan:         agentscan agent ./agent.yaml
              agentscan mcp   ./mcp.json | https://mcp.example.com
              agentscan supply pypi:langchain | npm:axios | hf:microsoft/phi-3 | dataset:org/name

Attack graph: agentscan graph agent ./agent.yaml [--export-html graph.html]
              agentscan graph mcp   ./mcp.json
              agentscan graph chain server1.json server2.json --calls "A->B"

Runtime:      agentscan runtime analyse  session.json
              agentscan runtime flow     --config agent.yaml --has-rag
              agentscan runtime identity --config agent.yaml

Compliance:   agentscan compliance map   ./agent.yaml
              agentscan compliance dpia  ./agent.yaml
              agentscan compliance audit ./agent.yaml --organisation "Acme" --output-file audit.pdf
        """)
    sub = parser.add_subparsers(dest="command", required=True)

    for name, help_text in [("agent","Scan agent config (YAML/JSON)"),
                             ("source","Scan real agent source code -- no config file needed"),
                             ("mcp","Scan MCP server"),
                             ("supply","Scan AI supply chain")]:
        p = sub.add_parser(name, help=help_text)
        if name == "agent":   p.add_argument("config")
        elif name == "source": p.add_argument("path", help="Python file or directory containing agent code")
        else:                 p.add_argument("target")
        p.add_argument("--output", choices=["text","json","sarif","html"], default="text")
        p.add_argument("--open", dest="open_browser", action="store_true",
                       help="Generate HTML report and open it in your browser automatically")
        p.add_argument("--verbose", action="store_true")
        p.add_argument("--fail-on", choices=["CRITICAL","HIGH","MEDIUM"])
        p.add_argument("--output-file")
        if name == "mcp": p.add_argument("--timeout", type=int, default=10)

    doctor_p = sub.add_parser("doctor", help="Check environment, detect frameworks and agent configs")
    doctor_p.add_argument("path", nargs="?", default=".", help="Path to scan (default: current directory)")

    sub.add_parser("demo", help="Run AgentScan against bundled vulnerable agents -- zero setup, no code of your own needed")
    sub.add_parser("benchmark", help="Run the evaluation kit and report pass/fail against documented thresholds")

    add_compliance_parser(sub)
    add_graph_parser(sub)
    add_runtime_parser(sub)

    args = parser.parse_args()

    if args.command == "compliance":
        {"map": cmd_map, "dpia": cmd_dpia, "audit": cmd_audit}[args.comp_command](args); return

    if args.command == "graph":
        {"agent": cmd_graph_agent, "mcp": cmd_graph_mcp, "chain": cmd_graph_chain,
         "trustflow": cmd_graph_trustflow, "escalation": cmd_graph_escalation,
         "query": cmd_graph_query}[args.graph_command](args); return

    if args.command == "runtime":
        {"analyse": cmd_runtime_analyse, "flow": cmd_prompt_flow, "identity": cmd_identity,
         "goals": cmd_goal_integrity}[args.rt_command](args); return

    if args.command == "doctor":
        results = run_doctor(args.path)
        print(render_doctor_report(results))
        return

    if args.command == "demo":
        sys.exit(run_demo())

    if args.command == "benchmark":
        sys.exit(run_benchmark())

    if args.command == "agent":      result = scan_agent_config(args.config)
    elif args.command == "source":   result = scan_source(args.path)
    elif args.command == "mcp":      result = scan_mcp(args.target, timeout=getattr(args,"timeout",10))
    elif args.command == "supply":   result = scan_supply_chain(args.target)
    else: parser.print_help(); sys.exit(1)

    # Exit 2 on scan errors (distinct from exit 1 = findings, exit 0 = clean).
    # This ensures CI/CD gates can distinguish "safe" from "scan failed to run".
    if result.error:
        print(f"Error: {result.error}", file=sys.stderr)
        sys.exit(2)

    # --open: generate HTML and launch browser regardless of --output flag
    open_browser = getattr(args, "open_browser", False)

    if _is_html(args.output) or open_browser:
        import tempfile
        if args.output_file:
            out_path = args.output_file
        elif open_browser:
            # Write to a temp file so nothing clutters the user's directory
            tmp = tempfile.NamedTemporaryFile(
                suffix=".html", prefix="agentscan_", delete=False
            )
            out_path = tmp.name
            tmp.close()
        else:
            out_path = "agentscan_report_" + result.scanner_type + ".html"

        path = generate_html_report(result, out_path, title=result.target)
        uri = Path(path).resolve().as_uri()

        print("")
        print("  AgentScan Report")
        print("  Risk score   : " + str(result.risk_score()) + "/100")
        print("  Findings     : " + str(len(result.reportable_findings)))
        print("  Attack paths : " + str(len(result.attack_paths)))
        print("  Report       : " + uri)

        if open_browser:
            try:
                import webbrowser
                webbrowser.open(uri)
                print("  Opening in your browser...")
            except Exception:
                print("  Could not open browser automatically.")
                print("  Copy the path above and paste it into your browser.")
    else:
        output = _output(result, args.output, args.verbose)
        if args.output_file:
            atomic_write_text(args.output_file, output, encoding="utf-8")
            if args.output == "text": print("Results written to " + args.output_file)
        else: print(output)
    if _should_fail(result, args.fail_on): sys.exit(1)

if __name__ == "__main__": main()
