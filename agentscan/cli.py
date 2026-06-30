"""AgentScan CLI v0.3.0"""
from __future__ import annotations
import argparse, sys
from pathlib import Path

from agentscan.scanners.agent_scanner import scan_agent_config
from agentscan.scanners.mcp_scanner import scan_mcp
from agentscan.scanners.supply_chain_scanner import scan_supply_chain
from agentscan.outputs.terminal import render_result
from agentscan.outputs.json_output import to_json, to_sarif
from agentscan.models import Severity
from agentscan.cli_compliance import add_compliance_parser, cmd_map, cmd_dpia, cmd_audit
from agentscan.graph.cli_graph import (add_graph_parser, cmd_graph_agent, cmd_graph_mcp, cmd_graph_chain,
                                        cmd_graph_trustflow, cmd_graph_escalation, cmd_graph_query)
from agentscan.runtime.cli_runtime import (add_runtime_parser, cmd_runtime_analyse, cmd_prompt_flow,
                                            cmd_identity, cmd_goal_integrity)


def _output(result, fmt, verbose):
    if fmt == "json":   return to_json(result)
    if fmt == "sarif":  return to_sarif(result)
    return render_result(result, verbose=verbose)

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
              agentscan graph chain server1.json server2.json --calls "A→B"

Runtime:      agentscan runtime analyse  session.json
              agentscan runtime flow     --config agent.yaml --has-rag
              agentscan runtime identity --config agent.yaml

Compliance:   agentscan compliance map   ./agent.yaml
              agentscan compliance dpia  ./agent.yaml
              agentscan compliance audit ./agent.yaml --organisation "Acme" --output-file audit.pdf
        """)
    sub = parser.add_subparsers(dest="command", required=True)

    for name, help_text in [("agent","Scan agent config"),("mcp","Scan MCP server"),("supply","Scan AI supply chain")]:
        p = sub.add_parser(name, help=help_text)
        if name == "agent": p.add_argument("config")
        else:               p.add_argument("target")
        p.add_argument("--output", choices=["text","json","sarif"], default="text")
        p.add_argument("--verbose", action="store_true")
        p.add_argument("--fail-on", choices=["CRITICAL","HIGH","MEDIUM"])
        p.add_argument("--output-file")
        if name == "mcp": p.add_argument("--timeout", type=int, default=10)

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

    if args.command == "agent":     result = scan_agent_config(args.config)
    elif args.command == "mcp":     result = scan_mcp(args.target, timeout=getattr(args,"timeout",10))
    elif args.command == "supply":  result = scan_supply_chain(args.target)
    else: parser.print_help(); sys.exit(1)

    output = _output(result, args.output, args.verbose)
    if args.output_file:
        Path(args.output_file).write_text(output, encoding="utf-8")
        if args.output == "text": print(f"Results written to {args.output_file}")
    else: print(output)
    if _should_fail(result, args.fail_on): sys.exit(1)

if __name__ == "__main__": main()
