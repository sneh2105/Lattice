"""Runtime, prompt flow, and identity CLI commands."""

from __future__ import annotations
import agentscan._compat  # force UTF-8 on Windows
import json, sys
from pathlib import Path

from agentscan.outputs.terminal import _col, BOLD, CYAN, RED, ORANGE, GREEN, DIM, YELLOW, RESET, BLUE
from agentscan.models import Severity


def _sev_col(sev):
    return {Severity.CRITICAL:RED, Severity.HIGH:ORANGE, Severity.MEDIUM:YELLOW}.get(sev, DIM)


def _risk_col(score: int) -> str:
    if score >= 70: return RED
    if score >= 40: return ORANGE
    if score >= 20: return YELLOW
    return GREEN


def cmd_runtime_analyse(args):
    """Analyse a runtime event log (JSONL or JSON array)."""
    from agentscan.runtime.events import AgentSession, RuntimeEvent, EventType
    from agentscan.runtime.analyser import RuntimeAnalyser

    path = Path(args.session_file)
    if not path.exists():
        print(f"Error: {path} not found", file=sys.stderr); sys.exit(1)

    raw = json.loads(path.read_text())
    events_data = raw if isinstance(raw, list) else raw.get("events", [])

    session = AgentSession(
        session_id=raw.get("session_id", "s1") if isinstance(raw, dict) else "s1",
        agent_id=raw.get("agent_id", "agent") if isinstance(raw, dict) else "agent",
    )
    for ed in events_data:
        try:
            session.add_event(RuntimeEvent(
                type=EventType(ed.get("type", "decision")),
                timestamp_ms=ed.get("timestamp_ms", 0),
                data=ed.get("data", {}),
            ))
        except Exception:
            pass

    report = RuntimeAnalyser().analyse(session)
    _render_runtime(report, args)


def _render_runtime(report, args):
    from agentscan.runtime.analyser import RuntimeAnalysisReport
    print(f"\n  {_col(BOLD+CYAN, 'Runtime Analysis')} — session {report.session_id}\n")
    print(f"  Agent: {report.agent_id}")
    print(f"  Events: {report.event_count}  Duration: {report.duration_ms}ms")
    print(f"  Critical findings: {_col(RED, str(sum(1 for f in report.findings if f.severity==Severity.CRITICAL)))}")
    print(f"  Attack paths: {_col(RED if report.attack_paths else GREEN, str(len(report.attack_paths)))}\n")

    if report.anomalies:
        print(_col(ORANGE+BOLD, "  Anomalies:"))
        for a in report.anomalies:
            print(f"    {_col(ORANGE, '[!]')} {a}")
        print()

    if report.attack_paths:
        print(_col(RED+BOLD, f"  Runtime Attack Paths ({len(report.attack_paths)}):"))
        for i, path in enumerate(report.attack_paths, 1):
            print(f"\n  {_col(RED, f'Path {i}:')} {_col(BOLD, path.title)}")
            print(f"  Score: {path.composite_score:.0f}  MITRE: {', '.join(path.mitre_atlas)}")
            print(f"  Chain ({len(path.events)} events):")
            for e in path.events:
                print(f"    {_col(DIM, '->')} {e.summary()}")
        print()

    if report.findings:
        print(_col(BOLD, f"  Findings ({len(report.findings)}):"))
        for f in report.findings:
            sc = _sev_col(f.severity)
            print(f"\n  {_col(sc, f'[{f.severity.value.upper()}]')} {_col(BOLD, f.title)}")
            print(f"  {_col(DIM, f.explanation[:200])}")
            print(f"  {_col(GREEN, 'Fix:')} {f.remediation[:150]}")
            if f.events:
                print(f"  {_col(DIM, 'Events: ' + ', '.join(e.summary()[:40] for e in f.events[:2]))}")
        print()

    print(_col(BOLD, "  Event Timeline:"))
    for entry in report.event_timeline:
        risk = _col(RED, '!') if entry.get("risk_signals") else _col(DIM, '-')
        type_str = _col(CYAN, entry['type'][:15])
        summ_str = _col(DIM, entry['summary'][:70])
        print(f"  {risk} t+{entry['t_ms']:>6}ms  {type_str:<30}  {summ_str}")
    print()


def cmd_prompt_flow(args):
    """Analyse prompt data flow — static or from session."""
    from agentscan.runtime.prompt_flow import PromptFlowAnalyser

    analyser = PromptFlowAnalyser()

    if args.session_file:
        from agentscan.runtime.events import AgentSession, RuntimeEvent, EventType
        path = Path(args.session_file)
        raw = json.loads(path.read_text())
        events_data = raw if isinstance(raw, list) else raw.get("events", [])
        session = AgentSession(
            session_id=raw.get("session_id","s1") if isinstance(raw, dict) else "s1",
            agent_id=raw.get("agent_id","agent") if isinstance(raw, dict) else "agent",
        )
        for ed in events_data:
            try:
                session.add_event(RuntimeEvent(
                    type=EventType(ed.get("type","decision")),
                    timestamp_ms=ed.get("timestamp_ms", 0),
                    data=ed.get("data", {}),
                ))
            except Exception:
                pass
        report = analyser.analyse_session(session)
    else:
        sys_prompt = args.system_prompt or ""
        tools = args.tools.split(",") if args.tools else []
        report = analyser.analyse_static(
            system_prompt=sys_prompt, tools=tools,
            has_rag=args.has_rag, has_memory=args.has_memory,
        )

    _render_prompt_flow(report)


def _render_prompt_flow(report):
    from agentscan.runtime.prompt_flow import PromptFlowReport
    print(f"\n  {_col(BOLD+CYAN, 'Prompt Flow Analysis')}\n")
    print(f"  {report.summary}\n")

    RISK_ICONS = {"critical": _col(RED,"●"), "high": _col(ORANGE,"●"),
                  "medium": _col(YELLOW,"●"), "low": _col(GREEN,"●"), "safe": _col(DIM,"○")}

    print(_col(BOLD, "  Flow stages:"))
    for node in report.nodes:
        icon = RISK_ICONS.get(node.risk_level, "○")
        tainted = _col(RED, " ← TAINTED") if node.id in report.injection_reach else ""
        secret = _col(RED, " ← SECRETS") if node.id in report.secret_exposure else ""
        print(f"  {icon} {_col(BOLD, node.label)}{tainted}{secret}")
        for fn in node.findings[:2]:
            print(f"      {_col(DIM, fn)}")
    print()

    if report.injection_reach:
        print(_col(RED+BOLD, f"  [!] Injection-reachable stages: {', '.join(report.injection_reach)}"))
    if report.secret_exposure:
        print(_col(RED+BOLD, f"  [!] Secrets found at: {', '.join(report.secret_exposure)}"))
    if report.rag_override_risk:
        print(_col(ORANGE, "  [!] RAG/memory can override system instructions"))
    if report.policy_bypass_risk:
        print(_col(ORANGE, "  [!] Policy bypass risk: injection can reach tools"))
    print()

    if report.findings:
        print(_col(BOLD, f"  Findings ({len(report.findings)}):"))
        for f in report.findings:
            sc = _sev_col(f.severity)
            print(f"  {_col(sc, f'[{f.severity.value}]')} {_col(BOLD, f.title)}")
            print(f"  {_col(DIM, f.explanation[:200])}")
            print(f"  {_col(GREEN, 'Fix:')} {f.remediation[:150]}\n")


def cmd_identity(args):
    """Build and display agent identity graph."""
    from agentscan.scanners.agent_scanner import scan_agent_config
    from agentscan.identity.agent_identity import identity_graph_from_scan, build_identity_graph

    if args.config:
        result = scan_agent_config(args.config)
        if result.error:
            print(f"Error: {result.error}", file=sys.stderr); sys.exit(1)
        ig = identity_graph_from_scan(result)
    else:
        print("Error: --config required", file=sys.stderr); sys.exit(1)

    _render_identity(ig)


def _render_identity(ig):
    from agentscan.identity.agent_identity import AgentIdentityGraph
    rc = _risk_col(ig.risk_score)

    print(f"\n  {_col(BOLD+CYAN, 'Agent Identity Graph')} — {ig.agent_name}\n")
    risk_bar = "#" * int(ig.risk_score/5) + "." * (20 - int(ig.risk_score/5))
    print(f"  Risk score  {_col(rc, f'{ig.risk_score:3d}/100')}  {_col(rc, risk_bar)}\n")

    # Yes/No answer panel
    print(_col(BOLD, "  What can this agent actually access?"))
    print(_col(DIM, "  " + "─"*55))
    checks = [
        ("Can access internet",          ig.can_access_internet),
        ("Can access secrets/credentials", ig.can_access_secrets),
        ("Can execute OS commands/code",  ig.can_execute_code),
        ("Can write to filesystem",       ig.can_write_filesystem),
        ("Can call cloud APIs",           ig.can_access_cloud),
        ("Can query databases",           ig.can_access_database),
        ("Can send emails",               ig.can_access_email),
        ("Has persistent memory",         ig.has_persistent_memory),
        ("Has explicit identity",         ig.identity_defined),
        ("Permissions scoped/minimal",    ig.permissions_scoped),
    ]
    for label, val in checks:
        icon = _col(RED, "[X] YES") if val and label != "Permissions scoped/minimal" and label != "Has explicit identity" \
               else _col(GREEN, "[OK] YES") if val \
               else _col(GREEN, "[OK] NO") if not val and label != "Has explicit identity" and label != "Permissions scoped/minimal" \
               else _col(ORANGE, "[X] NO")
        print(f"  {icon:<20} {label}")
    print()

    # Effective permissions
    if ig.effective_permissions:
        print(_col(BOLD, "  Effective permissions:"))
        for perm in ig.effective_permissions:
            print(f"    {_col(ORANGE, '•')} {perm}")
        print()

    # Node inventory
    cat_order = ["identity", "llm", "tool", "filesystem", "network", "database", "cloud", "secret", "memory", "vectordb"]
    print(_col(BOLD, "  Access inventory:"))
    seen_cats = set()
    for cat in cat_order:
        cat_nodes = [n for n in ig.nodes if n.category == cat]
        if not cat_nodes: continue
        if cat not in seen_cats:
            print(f"\n  {_col(DIM, cat.upper())}:")
            seen_cats.add(cat)
        for node in cat_nodes:
            scope_tag = _col(GREEN, "[scoped]") if node.scoped else _col(ORANGE, "[unscoped]")
            print(f"    {_col(BOLD, node.label)}  {scope_tag}  access={node.access_level}")
            for note in node.risk_notes[:1]:
                print(f"      {_col(DIM, note)}")
    print()

    # Findings
    if ig.findings:
        print(_col(BOLD, f"  Findings ({len(ig.findings)}):"))
        for f in ig.findings:
            sc = _sev_col(f.severity)
            print(f"  {_col(sc, f'[{f.severity.value}]')} {_col(BOLD, f.title)}")
            print(f"  {_col(DIM, f.explanation[:200])}")
            print(f"  {_col(GREEN, 'Fix:')} {f.remediation[:160]}\n")

    print(_col(DIM, f"  AgentScan v0.3.0 - identity graph\n"))


def add_runtime_parser(subparsers):
    rt = subparsers.add_parser("runtime", help="Runtime observability, prompt flow, and agent identity")
    rt_sub = rt.add_subparsers(dest="rt_command", required=True)

    # runtime analyse
    ra = rt_sub.add_parser("analyse", help="Analyse agent runtime event log")
    ra.add_argument("session_file", help="JSONL or JSON session file")
    ra.add_argument("--output-file", help="Write JSON report")

    # runtime flow
    rf = rt_sub.add_parser("flow", help="Prompt flow analysis — trace data through agent stages")
    rf.add_argument("--session-file", help="Runtime session JSON for dynamic analysis")
    rf.add_argument("--system-prompt", help="System prompt text for static analysis")
    rf.add_argument("--tools", help="Comma-separated tool names for static analysis")
    rf.add_argument("--has-rag", action="store_true")
    rf.add_argument("--has-memory", action="store_true")

    # runtime identity
    ri = rt_sub.add_parser("identity", help="Agent identity graph — what can this agent actually access?")
    ri.add_argument("--config", help="Agent config file")

    # runtime goals
    rg = rt_sub.add_parser("goals", help="Reasoning and goal integrity analysis")
    rg.add_argument("session_file", help="JSON session file")

    return rt


def cmd_goal_integrity(args):
    """agentscan runtime goals <session_file> — reasoning and goal integrity analysis."""
    from agentscan.runtime.events import AgentSession, RuntimeEvent, EventType
    from agentscan.runtime.goal_integrity import analyse_goal_integrity

    path = Path(args.session_file)
    if not path.exists():
        print(f"Error: {path} not found", file=sys.stderr); sys.exit(1)

    raw = json.loads(path.read_text())
    events_data = raw if isinstance(raw, list) else raw.get("events", [])
    session = AgentSession(
        session_id=raw.get("session_id","s1") if isinstance(raw, dict) else "s1",
        agent_id=raw.get("agent_id","agent") if isinstance(raw, dict) else "agent",
    )
    for ed in events_data:
        try:
            session.add_event(RuntimeEvent(
                type=EventType(ed.get("type","decision")),
                timestamp_ms=ed.get("timestamp_ms", 0),
                data=ed.get("data", {}),
            ))
        except Exception:
            pass

    report = analyse_goal_integrity(session)

    sc = RED if report.integrity_score < 50 else ORANGE if report.integrity_score < 80 else GREEN
    print(f"\n  {_col(BOLD+CYAN, 'Reasoning & Goal Integrity Analysis')} — session {session.session_id}\n")

    if report.declared_goal:
        print(f"  Declared goal ({report.declared_goal.source}):")
        print(f"    {_col(DIM, report.declared_goal.raw_text[:150])}")
        print(f"  Category: {report.declared_goal.category or '(unrecognised)'}  "
              f"Low-risk task: {report.declared_goal.is_low_risk}\n")
    else:
        print(f"  {_col(DIM, 'No declared goal extracted from session')}\n")

    bar = "#" * int(report.integrity_score/5) + "." * (20 - int(report.integrity_score/5))
    print(f"  Integrity score  {_col(sc, f'{report.integrity_score:3d}/100')}  {_col(sc, bar)}\n")

    print(f"  Tool calls analysed       : {report.tool_calls_analysed}")
    print(f"  Capability mismatches     : {_col(RED if report.mismatched_tool_calls else GREEN, str(report.mismatched_tool_calls))}")
    print(f"  Reasoning non-sequiturs   : {_col(RED if report.nonsequitur_count else GREEN, str(report.nonsequitur_count))}\n")

    if report.drift_events:
        print(_col(BOLD+RED, f"  Drift Events ({len(report.drift_events)}):"))
        for d in report.drift_events:
            sc2 = RED if d.severity.value == "CRITICAL" else ORANGE
            print(f"\n  {_col(sc2, f'[{d.severity.value}] {d.drift_type}')}")
            print(f"  {_col(DIM, d.explanation[:200])}")
            print(f"  Event: {_col(CYAN, d.event.summary()[:100])}")
        print()

    if report.findings:
        print(_col(BOLD, f"  Findings ({len(report.findings)}):"))
        for f in report.findings:
            sc2 = _sev_col(f.severity)
            print(f"  {_col(sc2, f'[{f.severity.value}]')} {_col(BOLD, f.title)}")
            print(f"  {_col(GREEN, 'Fix:')} {f.remediation[:150]}\n")
