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

def _serve_and_open(html_path: str) -> None:
    """
    Serve the HTML file over http://localhost so browsers don't block
    inline scripts (file:// URLs trigger CSP restrictions in Chrome/Edge
    that prevent inline JS from running, causing blank graphs/charts).
    Starts a one-shot HTTP server, opens the browser, then shuts down
    after the first request is served.
    """
    import http.server, threading, socket, sys, subprocess, time
    from pathlib import Path

    html_path = str(Path(html_path).resolve())
    directory = str(Path(html_path).parent)
    filename = Path(html_path).name

    # Find a free port
    with socket.socket() as s:
        s.bind(("", 0))
        port = s.getsockname()[1]

    url = "http://localhost:" + str(port) + "/" + filename

    class SilentHandler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=directory, **kwargs)
        def log_message(self, fmt, *args):
            pass  # suppress server log output

    server = http.server.HTTPServer(("localhost", port), SilentHandler)

    def shutdown_after_serve():
        # Give browser time to load all resources, then shut down
        time.sleep(30)
        server.shutdown()

    threading.Thread(target=shutdown_after_serve, daemon=True).start()

    print("  Serving report at " + url)

    # Open browser
    try:
        if sys.platform == "win32":
            subprocess.Popen(["cmd", "/c", "start", "", url],
                           shell=False, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        elif sys.platform == "darwin":
            subprocess.Popen(["open", url],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.Popen(["xdg-open", url],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("  Opening in your browser...")
    except Exception:
        print("  Open this URL in your browser: " + url)

    # Serve until shutdown (blocks for ~4 seconds)
    server.serve_forever()


def _open_in_browser(uri: str) -> None:
    """Wrapper: extract local path from file:// URI and serve over localhost."""
    if uri.startswith("file:///"):
        import sys
        if sys.platform == "win32":
            local_path = uri.replace("file:///", "").replace("/", "\\")
        else:
            local_path = uri.replace("file://", "")
        _serve_and_open(local_path)
    else:
        # Already an http URL, just open directly
        import subprocess, sys
        try:
            if sys.platform == "win32":
                subprocess.Popen(["cmd", "/c", "start", "", uri], shell=False,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", uri],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                subprocess.Popen(["xdg-open", uri],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            print("  Open this URL: " + uri)


def _is_html(fmt):
    return fmt == "html"

def _should_fail(result, fail_on):
    if not fail_on: return False
    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
    idx = order.index(Severity(fail_on.upper()))
    return any(order.index(f.severity) <= idx for f in result.reportable_findings if f.severity in order)

def _run_diff_command(args) -> None:
    """
    agentscan diff <target> [--save-baseline] [--fail-on-new] [--fail-on-escalated]

    Scans the target, then either saves the result as a new baseline or
    compares it against the previously saved one. Exit codes for CI use:
      0 = clean (no new/escalated findings, or --save-baseline succeeded)
      1 = --fail-on-new and a new finding was found, or --fail-on-escalated
          and a finding's severity increased
      2 = scan or baseline error
    """
    import json as _json
    from agentscan.ui_server import _build_merged_result, _serialize_result
    from agentscan.drift import save_baseline, compute_drift

    target = args.config
    result = _build_merged_result(target)
    if result.error:
        print("Error: " + result.error, file=sys.stderr)
        sys.exit(2)

    findings = _serialize_result(result)["findings"]

    if args.save_baseline:
        snapshot = save_baseline(target, findings)
        print("Baseline captured: " + snapshot["captured_at"] + " (" + str(len(findings)) + " findings)")
        sys.exit(0)

    drift = compute_drift(target, findings)
    if not drift["has_baseline"]:
        print("No baseline found for this target.")
        print("Capture one first: agentscan diff " + target + " --save-baseline")
        sys.exit(2)

    if args.output == "json":
        print(_json.dumps(drift, indent=2))
    else:
        s = drift["summary"]
        print("")
        print("  AgentScan Diff -- baseline captured " + drift["baseline_captured_at"])
        print("")
        print("  New:          " + str(s["new_count"]))
        print("  Resolved:     " + str(s["resolved_count"]))
        print("  Escalated:    " + str(s["escalated_count"]))
        print("  De-escalated: " + str(s["de_escalated_count"]))
        print("  Unchanged:    " + str(s["unchanged_count"]))
        print("")
        if drift["new"]:
            print("  New findings:")
            for f in drift["new"]:
                print("    [" + f["severity"] + "] " + f["title"])
            print("")
        if drift["escalated"]:
            print("  Escalated findings:")
            for e in drift["escalated"]:
                print("    " + e["finding"]["title"] + " (" + e["from"] + " -> " + e["to"] + ")")
            print("")

    if args.fail_on_new and drift["summary"]["new_count"] > 0:
        sys.exit(1)
    if args.fail_on_escalated and drift["summary"]["escalated_count"] > 0:
        sys.exit(1)
    sys.exit(0)


def _run_supply_manifest(manifest_path: str, max_packages: int) -> None:
    """
    agentscan supply --manifest requirements.txt|package.json|pyproject.toml

    Batch-scans every dependency listed in a manifest file. Reuses the same
    parsing the dashboard's Supply Chain tab uses, so CLI and dashboard
    results always agree.
    """
    from pathlib import Path
    p = Path(manifest_path)
    if not p.exists():
        print("Error: File not found: " + manifest_path, file=sys.stderr)
        sys.exit(2)

    name = p.name.lower()
    if name.startswith("requirements") and name.endswith(".txt"):
        pkg_manager = "pypi"
    elif name == "package.json":
        pkg_manager = "npm"
    elif name == "pyproject.toml":
        pkg_manager = "pyproject"
    else:
        print("Error: Unrecognized manifest file: " + manifest_path)
        print("Supported: requirements*.txt, package.json, pyproject.toml")
        sys.exit(2)

    content = p.read_text(encoding="utf-8", errors="ignore")

    from agentscan.ui_server import _get_supply_chain
    result = _get_supply_chain(content, pkg_manager, str(p))
    packages = result.get("packages", [])[:max_packages]
    total = result.get("total", len(packages))

    print("")
    print("  AgentScan Supply Chain -- " + manifest_path)
    print("  " + str(total) + " dependencies found" +
          (" (scanning first " + str(max_packages) + ")" if total > max_packages else ""))
    print("")

    label_w = 30
    print("  " + "Package".ljust(label_w) + " Risk    Status")
    print("  " + "-" * label_w + " ------- " + "-" * 30)

    any_findings = False
    for pkg in packages:
        pname = (pkg.get("package_name") or pkg.get("target") or "")[:label_w]
        if pkg.get("error"):
            print("  " + pname.ljust(label_w) + " -       Could not scan: " + str(pkg["error"])[:60])
            continue
        score = pkg.get("risk_score", 0)
        n_findings = len(pkg.get("findings", []))
        if n_findings > 0:
            any_findings = True
        status = "Clean" if score == 0 else (str(n_findings) + " finding(s)")
        print("  " + pname.ljust(label_w) + " " + str(score).rjust(3) + "/100 " + status)

    print("")
    sys.exit(1 if any_findings else 0)


def main():
    # Friendly redirect for common wrong commands
    import sys as _sys
    if len(_sys.argv) > 1 and _sys.argv[1] in ("scan", "check", "analyze", "analyse", "run"):
        wrong = _sys.argv[1]
        if len(_sys.argv) > 2:
            target = _sys.argv[2]
            target_path = Path(target)
            if target_path.exists() and target_path.suffix in (".yaml", ".yml", ".json"):
                print("\n  Tip: did you mean one of these?")
                print("    agentscan agent  " + target + "   (scan a config file)")
                print("    agentscan source " + target + "   (scan a Python source file)")
                print("")
            elif target_path.exists():
                print("\n  Tip: did you mean one of these?")
                print("    agentscan source " + target + "   (scan Python source code)")
                print("    agentscan agent  " + target + "   (scan a config file)")
                print("")
            else:
                print("\n  Tip: the command is 'source', 'agent', or 'mcp' -- not '" + wrong + "'")
                print("    agentscan source ./your-code/")
                print("    agentscan agent  ./your-agent.yaml")
                print("    agentscan demo                      # try it with no setup")
                print("")
        else:
            print("\n  Tip: the command is 'source', 'agent', or 'mcp' -- not '" + wrong + "'")
            print("    agentscan source ./your-code/")
            print("    agentscan agent  ./your-agent.yaml")
            print("    agentscan demo                      # try it with no setup")
            print("")
        _sys.exit(1)

    parser = argparse.ArgumentParser(prog="agentscan",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Quick start:
  agentscan demo                              # Try it with no setup -- 12 attack scenarios
  agentscan doctor .                          # Detect frameworks and tools in this directory
  agentscan source ./src/agents/ --open       # Scan Python source, open report in browser
  agentscan agent  ./agent.yaml  --open       # Scan a YAML/JSON config file
  agentscan mcp    ./server.json              # Scan an MCP server manifest

Scan your code:
  agentscan source ./path/to/agents/          # Scan a directory of Python files
  agentscan source ./agent.py                 # Scan a single file
  agentscan agent  ./agent.yaml               # Scan a declarative agent config
  agentscan mcp    https://mcp.example.com    # Scan a live MCP server

CI/CD (exit 1 if findings found, exit 2 if scan errored):
  agentscan source . --fail-on HIGH
  agentscan agent  ./agent.yaml --fail-on CRITICAL --output sarif --output-file results.sarif

Output formats:
  --output text    Terminal output (default)
  --output html    Self-contained HTML report (add --open to launch browser)
  --output json    Machine-readable JSON
  --output sarif   SARIF 2.1.0 (uploads to GitHub Security tab)

Attack graph:
  agentscan graph agent ./agent.yaml --open
  agentscan graph mcp   ./mcp.json

Compliance:
  agentscan compliance map   ./agent.yaml
  agentscan compliance audit ./agent.yaml --organisation "Acme" --output-file audit.pdf

Not sure where to start? Run: agentscan doctor .
""")
    sub = parser.add_subparsers(dest="command", required=True)

    # ── agent ──────────────────────────────────────────────────────────
    p_agent = sub.add_parser(
        "agent",
        help="Scan an agent config file (YAML or JSON)",
        description=(
            "Scan a YAML or JSON agent configuration for security vulnerabilities.\n"
            "Detects dangerous tool combinations, missing guardrails, and builds\n"
            "the full attack chain from entry point to impact.\n\n"
            "Examples:\n"
            "  agentscan agent ./agent.yaml\n"
            "  agentscan agent ./agent.yaml --open\n"
            "  agentscan agent ./agent.yaml --fail-on HIGH --output sarif --output-file results.sarif"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_agent.add_argument(
        "config",
        help="Path to a YAML or JSON agent config file (not a directory)"
    )

    # ── source ─────────────────────────────────────────────────────────
    p_source = sub.add_parser(
        "source",
        help="Scan Python agent source code (no config file needed)",
        description=(
            "Scan Python source files for agent tool definitions using AST analysis.\n"
            "Works with LangChain, CrewAI, AutoGen, OpenAI Agents SDK, PydanticAI,\n"
            "LlamaIndex, Haystack, Nova Act, Semantic Kernel, and raw API schemas.\n\n"
            "Examples:\n"
            "  agentscan source ./src/agents/\n"
            "  agentscan source ./agent.py --open\n"
            "  agentscan source . --fail-on CRITICAL"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_source.add_argument(
        "path",
        help="Python file or directory to scan (scans recursively)"
    )

    # ── mcp ────────────────────────────────────────────────────────────
    p_mcp = sub.add_parser(
        "mcp",
        help="Scan an MCP server (manifest file or live URL)",
        description=(
            "Scan an MCP server manifest file or a live MCP server endpoint.\n"
            "Detects dangerous tools, missing authentication, and cross-tool attack chains.\n\n"
            "Examples:\n"
            "  agentscan mcp ./mcp_server.json\n"
            "  agentscan mcp https://my-mcp-server.example.com"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_mcp.add_argument(
        "target",
        help="Path to an MCP manifest JSON file, OR a live server URL (https://...)"
    )
    p_mcp.add_argument("--timeout", type=int, default=10,
                       help="Timeout in seconds for live server requests (default: 10)")

    # ── supply ─────────────────────────────────────────────────────────
    p_supply = sub.add_parser(
        "supply",
        help="Scan AI supply chain (PyPI, npm, HuggingFace, datasets)",
        description=(
            "Scan AI packages, models, and datasets for supply-chain risks.\n\n"
            "Examples:\n"
            "  agentscan supply pypi:langchain\n"
            "  agentscan supply npm:@langchain/core\n"
            "  agentscan supply hf:microsoft/phi-3\n"
            "  agentscan supply dataset:openai/gsm8k\n\n"
            "  # Batch-scan every dependency in a manifest file:\n"
            "  agentscan supply --manifest requirements.txt\n"
            "  agentscan supply --manifest package.json\n"
            "  agentscan supply --manifest pyproject.toml"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_supply.add_argument(
        "target", nargs="?", default=None,
        help="Package to scan. Format: pypi:name | npm:name | hf:org/model | dataset:org/name"
    )
    p_supply.add_argument(
        "--manifest", metavar="FILE",
        help="Batch-scan every dependency in a requirements.txt / package.json / pyproject.toml file"
    )
    p_supply.add_argument(
        "--max-packages", type=int, default=20,
        help="Cap on how many dependencies to scan from a manifest (default: 20, avoids long CI runs)"
    )

    # ── shared output flags (applied to all four scan commands) ────────
    for p in [p_agent, p_source, p_mcp, p_supply]:
        p.add_argument(
            "--output", choices=["text","json","sarif","html"], default="text",
            help="Output format (default: text). html opens in browser, sarif uploads to GitHub Security tab"
        )
        p.add_argument(
            "--open", dest="open_browser", action="store_true",
            help="Generate an HTML report and open it in your browser automatically"
        )
        p.add_argument(
            "--verbose", action="store_true",
            help="Show full finding details including evidence and remediation"
        )
        p.add_argument(
            "--fail-on", choices=["CRITICAL","HIGH","MEDIUM"],
            help="Exit with code 1 if any finding at this severity or above is found (use in CI/CD)"
        )
        p.add_argument(
            "--output-file", metavar="FILE",
            help="Write output to this file instead of stdout"
        )

    doctor_p = sub.add_parser("doctor", help="Check environment, detect frameworks and agent configs")
    doctor_p.add_argument("path", nargs="?", default=".", help="Path to scan (default: current directory)")

    sub.add_parser("demo", help="Run AgentScan against bundled vulnerable agents -- zero setup, no code of your own needed")
    sub.add_parser("benchmark", help="Run the evaluation kit and report pass/fail against documented thresholds")

    diff_p = sub.add_parser(
        "diff", help="Compare a scan against a saved baseline -- new/resolved/escalated findings",
        description=(
            "Fingerprint-based drift detection between two scans of the same target.\n"
            "Findings are matched by id + tags, not exact wording, so re-phrasing a\n"
            "finding's description doesn't make it look like a new issue.\n\n"
            "Examples:\n"
            "  agentscan diff ./agent.yaml --save-baseline      # capture current scan as baseline\n"
            "  agentscan diff ./agent.yaml                      # compare against saved baseline\n"
            "  agentscan diff ./agent.yaml --fail-on-new         # exit 1 if any NEW finding (for CI)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    diff_p.add_argument("config", help="Path to the agent config, source file, or directory to scan")
    diff_p.add_argument("--save-baseline", action="store_true",
                        help="Capture the current scan as the new baseline instead of comparing")
    diff_p.add_argument("--fail-on-new", action="store_true",
                        help="Exit 1 if any new finding appears compared to the baseline (for CI/CD gates)")
    diff_p.add_argument("--fail-on-escalated", action="store_true",
                        help="Exit 1 if any finding's severity increased compared to the baseline")
    diff_p.add_argument("--output", choices=["text", "json"], default="text")

    ui_p = sub.add_parser("ui", help="Open the AgentScan web dashboard in your browser")
    ui_p.add_argument("--port", type=int, default=0, help="Port to run on (default: random free port)")
    ui_p.add_argument("--no-browser", action="store_true", help="Don't open browser automatically")

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

    if args.command == "diff":
        _run_diff_command(args)
        return

    if args.command == "ui":
        from agentscan.ui_server import run_ui
        run_ui(port=getattr(args, "port", 0), open_browser=not getattr(args, "no_browser", False))
        return

    if args.command == "agent":
        p = Path(args.config)
        if not p.exists():
            print("\n  Error: File not found: " + args.config)
            print("  Usage: agentscan agent ./your-agent.yaml")
            print("  Tip:   agentscan doctor .  -- to find agent configs in the current directory")
            sys.exit(2)
        if p.is_dir():
            print("\n  Error: '" + args.config + "' is a directory, not a config file.")
            print("  To scan a config file:  agentscan agent ./your-agent.yaml")
            print("  To scan source code:    agentscan source " + args.config)
            print("  To find configs:        agentscan doctor " + args.config)
            sys.exit(2)
        if p.suffix == ".py":
            print("\n  Error: '" + args.config + "' is a Python source file.")
            print("  agentscan agent expects a YAML or JSON agent config file.")
            print("  To scan Python source code:")
            print("    agentscan source " + args.config)
            sys.exit(2)
        result = scan_agent_config(args.config)

    elif args.command == "source":
        p = Path(args.path)
        if not p.exists():
            print("\n  Error: Path not found: " + args.path)
            print("  Usage: agentscan source ./your-agent.py")
            print("         agentscan source ./src/agents/")
            sys.exit(2)
        result = scan_source(args.path)

    elif args.command == "mcp":
        target = args.target
        if not target.startswith("http") and not Path(target).exists():
            print("\n  Error: File not found: " + target)
            print("  Usage: agentscan mcp ./mcp_server.json")
            print("         agentscan mcp https://my-mcp-server.example.com")
            sys.exit(2)
        if not target.startswith("http") and Path(target).is_dir():
            print("\n  Error: '" + target + "' is a directory.")
            print("  agentscan mcp expects a JSON manifest file or a live server URL.")
            print("  Usage: agentscan mcp ./mcp_server.json")
            sys.exit(2)
        result = scan_mcp(target, timeout=getattr(args,"timeout",10))

    elif args.command == "supply":
        manifest = getattr(args, "manifest", None)
        if manifest:
            _run_supply_manifest(manifest, getattr(args, "max_packages", 20))
            return

        target = args.target
        if not target:
            print("\n  Error: Provide a package (pypi:name) or --manifest FILE")
            print("  Examples:")
            print("    agentscan supply pypi:langchain")
            print("    agentscan supply --manifest requirements.txt")
            sys.exit(2)
        if not any(target.startswith(x) for x in ("pypi:","npm:","hf:","dataset:")):
            print("\n  Error: Supply chain target must start with pypi:, npm:, hf:, or dataset:")
            print("  Examples:")
            print("    agentscan supply pypi:langchain")
            print("    agentscan supply npm:@langchain/core")
            print("    agentscan supply hf:microsoft/phi-3")
            print("    agentscan supply dataset:openai/gsm8k")
            print("    agentscan supply --manifest requirements.txt")
            sys.exit(2)
        result = scan_supply_chain(target)

    else:
        parser.print_help()
        sys.exit(1)

    # Exit 2 on scan errors (distinct from exit 1 = findings, exit 0 = clean).
    # This ensures CI/CD gates can distinguish "safe" from "scan failed to run".
    if result.error:
        print("Error: " + str(result.error), file=sys.stderr)
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
            _open_in_browser(uri)
    else:
        output = _output(result, args.output, args.verbose)
        if args.output_file:
            atomic_write_text(args.output_file, output, encoding="utf-8")
            if args.output == "text": print("Results written to " + args.output_file)
        else: print(output)
    if _should_fail(result, args.fail_on): sys.exit(1)

if __name__ == "__main__": main()
