# -*- coding: utf-8 -*-
"""
Graph and MCP CLI commands.

  agentscan graph agent  <config>              Build + display attack graph
  agentscan graph mcp    <manifest|url>        Full MCP trust + risk + graph
  agentscan graph chain  <manifest1> <manifest2> [...]  Multi-server trust chain
  agentscan graph chain  ... --calls A->B        Declare A calls B
"""

from __future__ import annotations
import agentscan._compat  # force UTF-8 on Windows
import json
import sys
from pathlib import Path

from agentscan.scanners.agent_scanner import scan_agent_config
from agentscan.graph.engine import build_graph_from_scan, graph_paths_to_attack_paths
from agentscan.graph.visualiser import render_terminal, render_html
from agentscan.scanners.mcp_scanner_v2 import scan_mcp_v2
from agentscan.scanners.mcp_trust_chain import MCPTrustChain, MCPTrustChainReport
from agentscan.outputs.terminal import _col, BOLD, CYAN, RED, ORANGE, GREEN, DIM, YELLOW, RESET, BLUE
from agentscan.models import Severity


def _trust_colour(score: int) -> str:
    if score >= 70: return GREEN
    if score >= 40: return YELLOW
    if score >= 20: return ORANGE
    return RED


def _trust_level(score: int) -> str:
    if score >= 70: return "HIGH"
    if score >= 40: return "MEDIUM"
    if score >= 20: return "LOW"
    return "CRITICAL"


def cmd_graph_agent(args):
    result = scan_agent_config(args.config)
    if result.error:
        print(f"Error: {result.error}", file=sys.stderr); sys.exit(1)

    graph = build_graph_from_scan(result)
    paths = graph.find_attack_paths()
    print(render_terminal(graph, paths))

    print(_col(BOLD, "  Blast Radius Analysis"))
    print(_col(DIM, "  " + "─" * 60))
    for entry_id in ["user_prompt", "tool_response", "rag_context"]:
        br = graph.blast_radius(entry_id)
        if br["crown_jewels_reachable"]:
            print(f"  From '{_col(RED, br['entry_point'])}':")
            print(f"    Reachable nodes  : {br['reachable_nodes']}")
            print(f"    Crown jewels hit : {_col(RED, ', '.join(br['crown_jewels_reachable']))}")
            print(f"    Aggregate impact : {_col(RED, str(br['aggregate_impact']))}/100")
    print()

    if args.export_html or getattr(args, "open_browser", False):
        html = render_html(graph, paths, title=f"AgentScan — {args.config}")
        out_path = args.export_html or "agentscan_attack_graph.html"
        Path(out_path).write_text(html, encoding="utf-8")
        print(f"  Interactive graph -> {out_path}")
        if getattr(args, "open_browser", False):
            import webbrowser
            webbrowser.open(f"file://{Path(out_path).resolve()}")
            print(f"  Opened in your default browser.")
        print()


def cmd_graph_mcp(args):
    profile, result = scan_mcp_v2(args.target, timeout=getattr(args, "timeout", 10))
    if result.error:
        print(f"Error: {result.error}", file=sys.stderr); sys.exit(1)

    tc = _trust_colour(profile.trust_score)
    rc = RED if profile.risk_score >= 70 else ORANGE if profile.risk_score >= 40 else GREEN

    print(f"\n  {_col(BOLD+CYAN, 'MCP Security Platform')} — {profile.name}\n")
    print(f"  {'─'*60}")
    print(f"  Target    : {profile.url_or_path}")
    print(f"  Publisher : {profile.publisher}")
    print(f"  Live scan : {'Yes' if profile.is_live else 'No (manifest)'}")
    print(f"  Tools     : {profile.tool_count}\n")

    trust_bar = "#" * int(profile.trust_score/5) + "." * (20 - int(profile.trust_score/5))
    risk_bar  = "#" * int(profile.risk_score/5)  + "." * (20 - int(profile.risk_score/5))
    print(f"  Trust score  {_col(tc, f'{profile.trust_score:3d}/100')}  {_col(tc, trust_bar)}  [{profile.trust_level}]")
    print(f"  Risk score   {_col(rc, f'{profile.risk_score:3d}/100')}  {_col(rc, risk_bar)}\n")

    print(_col(BOLD, "  Trust deductions:"))
    for reason in profile.trust_deductions:
        col = GREEN if reason.startswith("[OK]") else ORANGE
        print(f"    {_col(col, reason)}")
    print()

    if profile.capabilities:
        print(_col(BOLD, "  Capabilities:"))
        cap_col = {"shell_exec": RED, "code_execution": RED, "secret_access": RED,
                   "cloud_api": ORANGE, "database": ORANGE, "file_write": ORANGE,
                   "network_egress": YELLOW, "file_read": YELLOW}
        for cap in sorted(profile.capabilities):
            print(f"    {_col(cap_col.get(cap, DIM), cap)}")
        print()

    print(_col(BOLD, "  Tools:"))
    for tool in profile.tools:
        if not tool.capabilities:
            print(f"    {_col(DIM, tool.name)}  {_col(DIM, '[safe]')}")
            continue
        sc = RED if tool.severity.value in ("CRITICAL","HIGH") else ORANGE if tool.severity.value=="MEDIUM" else DIM
        print(f"    {_col(sc,'●')} {_col(BOLD, tool.name)}  [{_col(sc, tool.severity.value)}]  "
              f"{_col(DIM, ', '.join(tool.capabilities))}")
    print()

    paths = profile.attack_paths
    print(render_terminal(profile.graph, paths))

    if args.export_html:
        html = render_html(profile.graph, paths, title=f"AgentScan MCP — {profile.name}")
        Path(args.export_html).write_text(html, encoding="utf-8")
        print(f"  Interactive graph -> {args.export_html}")
        print()


def cmd_graph_chain(args):
    """Multi-server trust chain analysis."""
    chain = MCPTrustChain()

    print(f"\n  {_col(BOLD+CYAN, 'MCP Multi-Server Trust Chain Analysis')}\n")
    print(f"  Scanning {len(args.targets)} server(s)...\n")

    names = []
    for target in args.targets:
        print(f"  {_col(DIM, '->')} {target}")
        name = chain.add_server(target, timeout=getattr(args, "timeout", 10))
        names.append(name)
        print(f"    {_col(GREEN, '[OK]')} {name}")

    # Parse --calls declarations (format: "ServerA->ServerB" or "ServerA->ServerB")
    if args.calls:
        for call_decl in args.calls:
            sep = "->" if "->" in call_decl else "->"
            parts = call_decl.split(sep)
            if len(parts) == 2:
                src, dst = parts[0].strip(), parts[1].strip()
                chain.declare_calls(src, dst)
                print(f"\n  {_col(DIM, 'Declared call:')} {src} -> {dst}")

    # Auto-declare sequential calls if --sequential flag
    if getattr(args, "sequential", False) and len(names) > 1:
        for i in range(len(names) - 1):
            chain.declare_calls(names[i], names[i+1])
            print(f"\n  {_col(DIM, 'Auto-declared call:')} {names[i]} -> {names[i+1]}")

    print(f"\n  {_col(DIM, 'Analysing trust chain...')}\n")
    report = chain.analyse()
    _render_chain_report(report, args)


def _render_chain_report(report: MCPTrustChainReport, args):
    """Render the multi-server trust chain report to terminal."""

    # ── Server overview table ────────────────────────────────────────────────
    print(_col(BOLD, "  ── Server Overview " + "─"*48))
    print()
    header = f"  {'Server':<28} {'Declared':>9} {'Effective':>10} {'Δ':>5}  {'Level':<10}  Capabilities"
    print(_col(DIM, header))
    print(_col(DIM, "  " + "─"*85))

    for name, result in report.trust_propagation.items():
        profile = report.server_profiles.get(name)
        caps = ", ".join(profile.capabilities[:4]) + ("…" if len(profile.capabilities) > 4 else "") if profile else ""
        dc = _trust_colour(result.declared_trust)
        ec = _trust_colour(result.effective_trust)
        delta = result.trust_reduction
        delta_str = _col(ORANGE, f"-{delta}") if delta > 0 else _col(GREEN, "  0")
        level = _trust_level(result.effective_trust)
        lc = _trust_colour(result.effective_trust)
        print(f"  {name:<28} {_col(dc, f'{result.declared_trust:>6}/100')}  "
              f"{_col(ec, f'{result.effective_trust:>6}/100')}  {delta_str:>8}  "
              f"{_col(lc, f'[{level}]'):<10}  {_col(DIM, caps)}")

    print()
    print(f"  Weakest server      : {_col(RED, report.weakest_server or 'N/A')}")
    print(f"  Effective trust floor: {_col(_trust_colour(report.effective_trust_floor), str(report.effective_trust_floor))}/100")
    print()

    # ── Trust propagation detail ─────────────────────────────────────────────
    poisoned = [(n, r) for n, r in report.trust_propagation.items() if r.trust_reduction > 0]
    if poisoned:
        print(_col(BOLD + ORANGE, "  ── Trust Pollution " + "─"*48))
        print()
        for name, result in poisoned:
            print(f"  {_col(ORANGE, '[!]')} '{_col(BOLD, name)}' trust reduced {result.declared_trust} -> {_col(RED, str(result.effective_trust))}/100")
            print(f"    Poisoned by : {_col(RED, ', '.join(result.poisoned_by))}")
            print(f"    Chain       : {' -> '.join(result.propagation_path)}")
            print()

    # ── Call graph ───────────────────────────────────────────────────────────
    if report.edges:
        print(_col(BOLD, "  ── Server Call Graph " + "─"*46))
        print()
        id_to_name = {}
        for name, profile in report.server_profiles.items():
            # Reconstruct id mapping from profile
            id_to_name[f"mcp_{list(report.server_profiles.keys()).index(name)+1}"] = name

        for edge in report.edges:
            src_name = id_to_name.get(edge.src_id, edge.src_id)
            dst_name = id_to_name.get(edge.dst_id, edge.dst_id)
            rel_col = GREEN if edge.declared else YELLOW
            rel_label = "declared" if edge.declared else "inferred"
            print(f"  {_col(CYAN, src_name)} ──{edge.relationship.replace('_','─')}──▶ "
                  f"{_col(CYAN, dst_name)}  {_col(rel_col, f'[{rel_label}]')}")
        print()

    # ── Cross-server attack paths ─────────────────────────────────────────────
    if report.cross_server_paths:
        crit_paths = [p for p in report.cross_server_paths if p.severity == Severity.CRITICAL]
        other_paths = [p for p in report.cross_server_paths if p.severity != Severity.CRITICAL]

        print(_col(BOLD + RED, f"  ── Cross-Server Attack Paths ({len(report.cross_server_paths)} found) " + "─"*30))
        print()

        for i, path in enumerate(report.cross_server_paths[:6], 1):
            sc = RED if path.severity == Severity.CRITICAL else ORANGE
            multi = f"  {_col(BOLD, f'[CROSSES {len(path.servers_involved)} SERVERS]')}" if len(path.servers_involved) >= 2 else ""
            print(f"  {_col(sc+BOLD, f'Path {i}:')} {path.title}{multi}")
            servers_str = " -> ".join(path.servers_involved) if path.servers_involved else "single"
            score_line = f"Score: {path.composite_score:.1f}  Servers: {servers_str}"
            print(f"  {_col(DIM, score_line)}")
            print()
            for j, step in enumerate(path.step_labels):
                indent = "  " * (j+1)
                col = RED if j == 0 or j == len(path.step_labels)-1 else CYAN
                print(f"  {indent}{_col(col, step)}")
                if j < len(path.step_labels) - 1:
                    print(f"  {indent}  {_col(DIM, chr(8595))}")
            print()
            if path.mitre_atlas:
                print(f"  {_col(DIM, 'MITRE: ' + ', '.join(path.mitre_atlas))}")
            print(f"  {_col(DIM, chr(8212)*60)}")
            print()

    # ── Findings ─────────────────────────────────────────────────────────────
    if report.findings:
        print(_col(BOLD, f"  ── Findings ({len(report.findings)}) " + "─"*52))
        print()
        for f in report.findings:
            sc = RED if f.severity == Severity.CRITICAL else ORANGE if f.severity == Severity.HIGH else YELLOW
            print(f"  {_col(sc, f'[{f.severity.value}]')} {_col(BOLD, f.title)}")
            print(f"  {_col(DIM, f.explanation[:200])}")
            print(f"  {_col(GREEN, 'Fix:')} {f.remediation[:150]}")
            print()

    # ── JSON export ──────────────────────────────────────────────────────────
    if getattr(args, "output_file", None):
        import json as _json
        data = {
            "scan_duration_ms": report.scan_duration_ms,
            "servers": {
                name: {
                    "declared_trust": r.declared_trust,
                    "effective_trust": r.effective_trust,
                    "trust_level": _trust_level(r.effective_trust),
                    "poisoned_by": r.poisoned_by,
                    "capabilities": report.server_profiles[name].capabilities if name in report.server_profiles else [],
                    "risk_score": report.server_profiles[name].risk_score if name in report.server_profiles else 0,
                }
                for name, r in report.trust_propagation.items()
            },
            "effective_trust_floor": report.effective_trust_floor,
            "weakest_server": report.weakest_server,
            "cross_server_attack_paths": [
                {
                    "title": p.title,
                    "severity": p.severity.value,
                    "score": p.composite_score,
                    "servers": p.servers_involved,
                    "chain": p.step_labels,
                    "mitre": p.mitre_atlas,
                }
                for p in report.cross_server_paths
            ],
            "findings": [
                {"id": f.id, "title": f.title, "severity": f.severity.value}
                for f in report.findings
            ],
        }
        Path(args.output_file).write_text(_json.dumps(data, indent=2), encoding="utf-8")
        print(f"  {_col(GREEN, '[OK]')} JSON report -> {args.output_file}")

    # ── HTML export ──────────────────────────────────────────────────────────
    if getattr(args, "export_html", None):
        html = render_html(
            report.unified_graph,
            graph_paths_to_attack_paths(
                report.unified_graph.find_attack_paths()
            ) if False else [],
            title="AgentScan — Multi-Server Trust Chain"
        )
        # Pass actual GraphPath objects
        from agentscan.graph.engine import graph_paths_to_attack_paths as gp2ap
        from agentscan.graph.engine import AttackGraph
        actual_paths = report.unified_graph.find_attack_paths()
        html = render_html(report.unified_graph, actual_paths, "AgentScan — Trust Chain")
        Path(args.export_html).write_text(html, encoding="utf-8")
        print(f"  {_col(GREEN, '[OK]')} Interactive graph -> {args.export_html}")

    print(f"\n  {_col(DIM, f'AgentScan v0.2.0 - scan took {report.scan_duration_ms}ms')}\n")


def add_graph_parser(subparsers):
    graph_p = subparsers.add_parser("graph", help="Attack graph, MCP trust scoring, and multi-server trust chains")
    graph_sub = graph_p.add_subparsers(dest="graph_command", required=True)

    # graph agent
    agent_p = graph_sub.add_parser("agent", help="Build attack graph from agent config")
    agent_p.add_argument("config")
    agent_p.add_argument("--export-html", metavar="FILE")
    agent_p.add_argument("--open", dest="open_browser", action="store_true",
                         help="Open the attack graph directly in your browser (no server, no login)")

    # graph mcp
    mcp_p = graph_sub.add_parser("mcp", help="Full MCP trust + risk + graph analysis")
    mcp_p.add_argument("target")
    mcp_p.add_argument("--timeout", type=int, default=10)
    mcp_p.add_argument("--export-html", metavar="FILE")

    # graph chain
    chain_p = graph_sub.add_parser("chain", help="Multi-server trust chain analysis")
    chain_p.add_argument("targets", nargs="+", help="Two or more MCP server manifests or URLs")
    chain_p.add_argument("--calls", nargs="*", metavar="A->B",
                         help="Declare server call relationships, e.g. --calls 'ServerA->ServerB'")
    chain_p.add_argument("--sequential", action="store_true",
                         help="Auto-declare calls in sequence: target1->target2->target3")
    chain_p.add_argument("--timeout", type=int, default=10)
    chain_p.add_argument("--output-file", metavar="FILE", help="Write JSON report to file")
    chain_p.add_argument("--export-html", metavar="FILE", help="Export interactive HTML graph")

    # graph trustflow
    tf_p = graph_sub.add_parser("trustflow", help="Trust boundary crossing analysis")
    tf_p.add_argument("config")

    # graph escalation
    esc_p = graph_sub.add_parser("escalation", help="Capability escalation analysis")
    esc_p.add_argument("config")

    # graph query (AI-SQL)
    q_p = graph_sub.add_parser("query", help="Query the attack graph with AI-SQL")
    q_p.add_argument("config")
    q_p.add_argument("sql", nargs="?", default=None, help="AI-SQL query string")

    return graph_p


def cmd_graph_trustflow(args):
    """agentscan graph trustflow <config> — trust boundary crossing analysis."""
    from agentscan.scanners.agent_scanner import scan_agent_config
    from agentscan.graph.engine import build_graph_from_scan
    from agentscan.graph.trust_flow import analyse_trust_flow

    result = scan_agent_config(args.config)
    if result.error:
        print(f"Error: {result.error}", file=sys.stderr); sys.exit(1)

    graph = build_graph_from_scan(result)
    report = analyse_trust_flow(graph)

    print(f"\n  {_col(BOLD+CYAN, 'Trust Flow Analysis')} — {args.config}\n")
    print(f"  Unsanitised trust boundary crossings: {_col(RED, str(report.total_unsanitised_crossings))}\n")

    if report.crossings:
        print(_col(BOLD, "  Trust Boundary Crossings:"))
        for c in report.crossings:
            san = _col(GREEN, "[sanitised]") if c.is_sanitised else _col(RED, "[UNSANITISED]")
            print(f"  {san} {_col(CYAN, c.src_node.label)} [{c.src_trust.value}] "
                  f"-> {_col(CYAN, c.dst_node.label)} [{c.dst_trust.value}]")
            print(f"    {_col(DIM, c.description[:100])}")
        print()

    if report.riskiest_path:
        rp = report.riskiest_path
        print(_col(RED+BOLD, f"  Riskiest trust flow path: {rp.title}"))
        trust_chain = " -> ".join(f"{n.label}[{t.value}]" for n, t in zip(rp.nodes, rp.trust_levels))
        print(f"    {_col(DIM, trust_chain)}")
        print(f"    Unsanitised crossings on this path: {_col(RED, str(rp.unsanitised_crossings))}\n")

    if report.findings:
        print(_col(BOLD, f"  Findings ({len(report.findings)}):"))
        for f in report.findings[:8]:
            sc = RED if f.severity.value == "CRITICAL" else ORANGE
            print(f"  {_col(sc, f'[{f.severity.value}]')} {_col(BOLD, f.title)}")
            print(f"  {_col(GREEN, 'Fix:')} {f.remediation[:140]}\n")


def cmd_graph_escalation(args):
    """agentscan graph escalation <config> — capability escalation analysis."""
    from agentscan.scanners.agent_scanner import scan_agent_config
    from agentscan.graph.escalation import analyse_capability_escalation

    result = scan_agent_config(args.config)
    if result.error:
        print(f"Error: {result.error}", file=sys.stderr); sys.exit(1)

    caps = result.metadata.get("capabilities_detected", [])
    report = analyse_capability_escalation(caps)

    print(f"\n  {_col(BOLD+CYAN, 'Capability Escalation Analysis')} — {args.config}\n")
    print(f"  Declared capabilities : {', '.join(sorted(report.declared_capabilities)) or '(none)'}")
    print(f"  Declared risk         : {report.declared_risk}/100")
    print(f"  Effective risk        : {_col(RED, str(report.effective_risk))}/100")
    ef_col = RED if report.escalation_factor >= 1.5 else ORANGE if report.escalation_factor > 1.0 else GREEN
    print(f"  Escalation factor     : {_col(ef_col, f'{report.escalation_factor}x')}\n")

    new_caps = report.effective_capabilities - report.declared_capabilities
    if new_caps:
        print(_col(RED+BOLD, f"  Hidden effective capabilities: {', '.join(sorted(new_caps))}\n"))

    if report.escalation_paths:
        print(_col(BOLD, "  Escalation paths:"))
        for p in report.escalation_paths:
            sc = RED if p.severity.value == "CRITICAL" else ORANGE
            print(f"  {_col(sc, f'[{p.severity.value}]')} {sorted(p.required_caps)} "
                  f"{_col(DIM, '->')} {_col(BOLD, p.escalates_to)}  (+{p.risk_delta} risk)")
            print(f"    {_col(DIM, p.explanation[:140])}")
        print()

    if report.findings:
        print(_col(BOLD, f"  Findings ({len(report.findings)}):"))
        for f in report.findings[:6]:
            sc = RED if f.severity.value == "CRITICAL" else ORANGE
            print(f"  {_col(sc, f'[{f.severity.value}]')} {_col(BOLD, f.title)}")
            print(f"  {_col(GREEN, 'Fix:')} {f.remediation[:140]}\n")


def cmd_graph_query(args):
    """agentscan graph query <config> "<AI-SQL query>" """
    from agentscan.scanners.agent_scanner import scan_agent_config
    from agentscan.graph.engine import build_graph_from_scan
    from agentscan.graph.ai_sql import AISQLEngine, QUERY_EXAMPLES

    result = scan_agent_config(args.config)
    if result.error:
        print(f"Error: {result.error}", file=sys.stderr); sys.exit(1)

    graph = build_graph_from_scan(result)
    engine = AISQLEngine(graph)

    if not args.sql:
        print(f"\n  {_col(BOLD+CYAN, 'AI-SQL Query Engine')}\n")
        print(_col(BOLD, "  Example queries:"))
        for ex in QUERY_EXAMPLES:
            print(f"    {_col(DIM, ex)}")
        print()
        return

    result_q = engine.query(args.sql)

    print(f"\n  {_col(BOLD+CYAN, 'AI-SQL')} {_col(DIM, '›')} {args.sql}\n")
    if not result_q.success:
        print(f"  {_col(RED, 'Error:')} {result_q.error}\n")
        return

    print(f"  {_col(DIM, result_q.explanation)}\n")
    if result_q.rows:
        # Print as simple table
        keys = list(result_q.rows[0].keys())
        for row in result_q.rows:
            vals = "  ".join(f"{k}={v}" for k, v in row.items())
            print(f"    {_col(CYAN, vals[:150])}")
    print()


def add_query_examples_help():
    return QUERY_EXAMPLES if 'QUERY_EXAMPLES' in dir() else []
