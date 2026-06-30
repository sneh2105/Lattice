"""
Compliance CLI extension — adds 'agentscan compliance' subcommands.

agentscan compliance map   <scan_target>    Map findings to framework controls
agentscan compliance dpia  <scan_target>    Generate DPIA document
agentscan compliance audit <scan_target>    Generate full PDF audit report
"""

from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

from agentscan.scanners.agent_scanner import scan_agent_config
from agentscan.scanners.mcp_scanner import scan_mcp
from agentscan.compliance.framework_mapper import map_findings_to_controls
from agentscan.compliance.dpia import generate_dpia
from agentscan.compliance.audit_report import generate_audit_report
from agentscan.outputs.terminal import _col, BOLD, CYAN, GREEN, ORANGE, RED, DIM, RESET, BLUE


def _detect_scanner(target: str):
    """Auto-detect which scanner to run based on target."""
    if target.startswith("http://") or target.startswith("https://"):
        return scan_mcp(target)
    path = Path(target)
    if path.exists():
        # Sniff content to decide agent vs mcp
        try:
            import json, yaml
            text = path.read_text()
            data = yaml.safe_load(text) if path.suffix in ('.yaml', '.yml') else json.loads(text)
            if isinstance(data, dict) and "tools" in data and any(
                isinstance(t, dict) and "inputSchema" in t for t in data.get("tools", [])
            ):
                return scan_mcp(target)
        except Exception:
            pass
        return scan_agent_config(target)
    return scan_agent_config(target)


def cmd_map(args):
    """agentscan compliance map <target> — print framework control mapping."""
    result = _detect_scanner(args.target)
    if result.error:
        print(f"Scan error: {result.error}", file=sys.stderr)
        sys.exit(1)

    report = map_findings_to_controls(result)

    print(f"\n  {_col(BOLD + CYAN, 'AgentScan Compliance Map')} — {args.target}\n")
    print(f"  Overall posture: {_col(RED if report.overall_posture == 'non-compliant' else ORANGE if report.overall_posture == 'partial' else GREEN, report.overall_posture.upper())}")
    print(f"  Frameworks covered: {', '.join(report.frameworks_covered)}\n")

    if report.priority_gaps:
        print(_col(RED, "  Priority actions:"))
        for i, gap in enumerate(report.priority_gaps, 1):
            print(f"    {i}. {gap}")
        print()

    print(_col(BOLD, "  Controls implicated by framework:"))
    for fw, count in sorted(report.control_summary.items(), key=lambda x: -x[1]):
        print(f"    {_col(ORANGE, str(count)):>3} controls  {fw}")

    print()
    print(_col(BOLD, "  Finding → Control mapping:"))
    for mapping in report.mappings:
        print(f"\n  {_col(CYAN, mapping.finding_title)} [{mapping.finding_severity}]")
        for ctrl in mapping.controls:
            mand = _col(RED, "mandatory") if ctrl.severity == "mandatory" else _col(BLUE, "recommended")
            print(f"    {mand}  {ctrl.framework}  {_col(ORANGE, ctrl.control_id)}  {ctrl.control_name}")

    print(f"\n  {_col(DIM, 'AgentScan v0.1.0 · github.com/sneh2105/agentscan')}\n")


def cmd_dpia(args):
    """agentscan compliance dpia <target> — generate DPIA."""
    result = _detect_scanner(args.target)
    if result.error:
        print(f"Scan error: {result.error}", file=sys.stderr)
        sys.exit(1)

    dpia = generate_dpia(result, agent_name=args.agent_name, assessor=args.assessor)

    if args.output_file:
        out = json.dumps({
            "agent_name": dpia.agent_name,
            "assessment_date": dpia.assessment_date,
            "overall_risk_level": dpia.overall_risk_level,
            "recommended_action": dpia.recommended_action,
            "frameworks": dpia.compliance_frameworks,
            "sections": [
                {"title": s.title, "status": s.status, "content": s.content, "controls": s.controls}
                for s in dpia.sections
            ],
            "open_gaps": dpia.open_gaps,
        }, indent=2)
        Path(args.output_file).write_text(out)
        print(f"DPIA written to {args.output_file}")
    else:
        risk_col = RED if dpia.overall_risk_level in ("critical", "high") else ORANGE if dpia.overall_risk_level == "medium" else GREEN
        rec_col = RED if dpia.recommended_action == "do-not-deploy" else ORANGE if "controls" in dpia.recommended_action else GREEN

        print(f"\n  {_col(BOLD + CYAN, 'Data Protection Impact Assessment')} — {dpia.agent_name}\n")
        print(f"  Risk level    : {_col(risk_col, dpia.overall_risk_level.upper())}")
        print(f"  Recommendation: {_col(rec_col, dpia.recommended_action.upper().replace('-', ' '))}")
        print(f"  Frameworks    : {', '.join(dpia.compliance_frameworks)}\n")

        for section in dpia.sections:
            status_col = GREEN if section.status == "adequate" else ORANGE if section.status == "gap" else DIM
            print(_col(BOLD, f"  {section.title}") + " " + _col(status_col, f"[{section.status.upper()}]"))
            for line in section.content.split("\n"):
                if line.strip():
                    print(f"    {line}")
            print()

        if dpia.open_gaps:
            print(_col(ORANGE, "  Open gaps requiring manual review:"))
            for gap in dpia.open_gaps:
                print(f"    • {gap}")
        print()


def cmd_audit(args):
    """agentscan compliance audit <target> — generate PDF audit report."""
    result = _detect_scanner(args.target)
    if result.error:
        print(f"Scan error: {result.error}", file=sys.stderr)
        sys.exit(1)

    output = args.output_file or f"agentscan_audit_{Path(args.target).stem}.pdf"
    print(f"Generating audit report...")
    path = generate_audit_report(
        result,
        output_path=output,
        agent_name=args.agent_name,
        organisation=args.organisation,
        assessor=args.assessor,
        include_dpia=not args.no_dpia,
    )
    print(f"✓ Audit report written to: {path}")
    print(f"  Risk score    : {result.risk_score()}/100")
    print(f"  Findings      : {len(result.reportable_findings)}")
    print(f"  Attack paths  : {len(result.attack_paths)}")
    print(f"  Frameworks    : RBI · DPDP · SEBI · ISO 42001 · EU AI Act · SOC 2")


def add_compliance_parser(subparsers):
    """Add 'compliance' subcommand group to main CLI."""
    comp = subparsers.add_parser("compliance", help="Compliance mapping, DPIA, and audit report generation")
    comp_sub = comp.add_subparsers(dest="comp_command", required=True)

    # map
    map_p = comp_sub.add_parser("map", help="Map findings to framework controls (RBI, DPDP, ISO 42001, EU AI Act, SOC 2)")
    map_p.add_argument("target", help="Agent config file or MCP server URL")

    # dpia
    dpia_p = comp_sub.add_parser("dpia", help="Generate a Data Protection Impact Assessment")
    dpia_p.add_argument("target", help="Agent config file or MCP server URL")
    dpia_p.add_argument("--agent-name", default="AI Agent")
    dpia_p.add_argument("--assessor", default="AgentScan")
    dpia_p.add_argument("--output-file", help="Save DPIA as JSON to this file")

    # audit
    audit_p = comp_sub.add_parser("audit", help="Generate full PDF audit report")
    audit_p.add_argument("target", help="Agent config file or MCP server URL")
    audit_p.add_argument("--agent-name", default="AI Agent")
    audit_p.add_argument("--organisation", default="Organisation")
    audit_p.add_argument("--assessor", default="AgentScan")
    audit_p.add_argument("--output-file", help="Output PDF path")
    audit_p.add_argument("--no-dpia", action="store_true", help="Exclude DPIA section")

    return comp
