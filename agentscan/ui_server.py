# -*- coding: utf-8 -*-
"""
AgentScan Dashboard Backend
============================
Flask API server for the web dashboard.
agentscan ui -> starts this -> opens browser
"""
from __future__ import annotations
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path


def _severity_str(f) -> str:
    return f.severity.value if hasattr(f.severity, "value") else str(f.severity)


def _result_to_dict(result) -> dict:
    def finding_dict(f):
        return {
            "id": f.id,
            "title": f.title,
            "severity": _severity_str(f),
            "confidence": f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence),
            "explanation": getattr(f, "explanation", ""),
            "impact": getattr(f, "impact", ""),
            "remediation": getattr(f, "remediation", ""),
            "mitre_atlas": list(getattr(f, "mitre_atlas", []) or []),
            "evidence": [
                {"source": e.source, "observed_value": str(e.observed_value)}
                for e in (getattr(f, "evidence", []) or [])
            ],
            "tags": list(getattr(f, "tags", []) or []),
        }

    def path_dict(p):
        return {
            "id": p.id,
            "title": p.title,
            "severity": p.severity.value if hasattr(p.severity, "value") else str(p.severity),
            "entry_point": getattr(p, "entry_point", ""),
            "impact": getattr(p, "impact", ""),
            "description": getattr(p, "description", ""),
            "mitre_atlas": list(getattr(p, "mitre_atlas", []) or []),
            "steps": [
                {"id": s.id, "title": s.title,
                 "severity": s.severity.value if hasattr(s.severity, "value") else str(s.severity)}
                for s in (getattr(p, "steps", []) or [])
            ],
        }

    score = result.risk_score() if callable(getattr(result, "risk_score", None)) else 0
    counts = {}
    for f in (result.findings or []):
        s = _severity_str(f)
        counts[s] = counts.get(s, 0) + 1

    return {
        "target": result.target,
        "scanner_type": result.scanner_type,
        "risk_score": score,
        "error": result.error,
        "findings": [finding_dict(f) for f in (result.findings or [])],
        "attack_paths": [path_dict(p) for p in (result.attack_paths or [])],
        "summary": counts,
        "metadata": result.metadata or {},
    }


def _auto_detect_and_scan(target: str) -> dict:
    """
    Auto-detect what kind of target this is and route to the right scanner.
    Returns a dict with result + detected_type.
    """
    from pathlib import Path

    target = target.strip()

    # Supply chain identifiers
    for prefix in ("pypi:", "npm:", "hf:", "dataset:"):
        if target.startswith(prefix):
            from agentscan.scanners.supply_chain_scanner import scan_supply_chain
            result = scan_supply_chain(target)
            return {"type": "supply", **_result_to_dict(result)}

    # Live URL -> MCP
    if target.startswith("http://") or target.startswith("https://"):
        from agentscan.scanners.mcp_scanner import scan_mcp
        result = scan_mcp(target)
        return {"type": "mcp", **_result_to_dict(result)}

    p = Path(target)

    if not p.exists():
        return {"error": "Path not found: " + target, "type": "unknown"}

    if p.is_dir():
        # Directory -> source scan
        from agentscan.scanners.source_scanner import scan_source
        result = scan_source(target)
        d = _result_to_dict(result)
        d["type"] = "source"
        return d

    # File - detect by extension and content
    ext = p.suffix.lower()

    if ext == ".py":
        from agentscan.scanners.source_scanner import scan_source
        result = scan_source(target)
        d = _result_to_dict(result)
        d["type"] = "source"
        return d

    if ext in (".yaml", ".yml", ".json"):
        # Sniff content to decide agent vs mcp
        try:
            import yaml as _yaml
            text = p.read_text(encoding="utf-8", errors="ignore")
            data = _yaml.safe_load(text) if ext in (".yaml", ".yml") else json.loads(text)

            # MCP if tools have inputSchema
            if isinstance(data, dict):
                tools = data.get("tools", [])
                if tools and any(isinstance(t, dict) and "inputSchema" in t for t in tools[:5]):
                    from agentscan.scanners.mcp_scanner import scan_mcp
                    result = scan_mcp(target)
                    d = _result_to_dict(result)
                    d["type"] = "mcp"
                    return d

                # n8n / Flowise / Dify detection
                if "nodes" in data or "model_config" in data:
                    from agentscan.scanners.agent_scanner import scan_agent_config
                    result = scan_agent_config(target)
                    d = _result_to_dict(result)
                    d["type"] = "agent"
                    return d

        except Exception:
            pass

        from agentscan.scanners.agent_scanner import scan_agent_config
        result = scan_agent_config(target)
        d = _result_to_dict(result)
        d["type"] = "agent"
        return d

    return {"error": "Cannot determine scan type for: " + target + "\nSupported: .py, .yaml, .yml, .json files, folders, URLs, pypi:/npm:/hf:/dataset: identifiers", "type": "unknown"}


def _get_compliance(target: str) -> dict:
    """Run compliance mapping on a target."""
    try:
        from agentscan.cli_compliance import _detect_scanner
        from agentscan.compliance.framework_mapper import map_findings_to_controls
        result = _detect_scanner(target)
        if result.error:
            return {"error": result.error}
        report = map_findings_to_controls(result)
        # Serialize the compliance report
        controls = []
        for fc in getattr(report, "finding_control_mappings", []):
            controls.append({
                "finding_id": getattr(fc, "finding_id", ""),
                "finding_title": getattr(fc, "finding_title", ""),
                "severity": getattr(fc, "severity", ""),
                "controls": [
                    {"framework": c.framework, "control_id": c.control_id,
                     "control_name": getattr(c, "control_name", ""),
                     "requirement": getattr(c, "requirement", "")}
                    for c in (getattr(fc, "controls", []) or [])
                ],
            })
        return {
            "overall_posture": getattr(report, "overall_posture", "UNKNOWN"),
            "frameworks": getattr(report, "frameworks_covered", []),
            "priority_actions": getattr(report, "priority_actions", []),
            "finding_control_mappings": controls,
        }
    except Exception as e:
        return {"error": str(e)}


def _run_doctor(path: str) -> dict:
    """Run agentscan doctor and return structured results."""
    from agentscan.doctor import run_doctor
    results = run_doctor(path)
    return [
        {
            "label": r.label,
            "found": r.found,
            "detail": r.detail,
            "suggested_command": r.suggested_command,
            "severity": r.severity,
        }
        for r in results
    ]


def create_app(version: str = "0.2.6") -> "Flask":
    from flask import Flask, request, jsonify, Response
    from agentscan.ui_html import get_dashboard_html

    app = Flask(__name__)

    @app.route("/")
    def index():
        return Response(get_dashboard_html(version), mimetype="text/html")

    @app.route("/api/scan", methods=["POST"])
    def api_scan():
        data = request.get_json(force=True) or {}
        target = (data.get("target") or "").strip()
        force_type = data.get("force_type")  # if user explicitly picks a type

        if not target:
            return jsonify({"error": "No target provided"}), 400

        try:
            if force_type == "demo":
                r = subprocess.run(
                    ["agentscan", "demo"],
                    capture_output=True, text=True, encoding="utf-8", timeout=120
                )
                return jsonify({"type": "demo", "output": r.stdout + r.stderr})

            result = _auto_detect_and_scan(target)
            return jsonify(result)
        except Exception as e:
            import traceback
            return jsonify({"error": str(e), "detail": traceback.format_exc()}), 500

    @app.route("/api/compliance", methods=["POST"])
    def api_compliance():
        data = request.get_json(force=True) or {}
        target = (data.get("target") or "").strip()
        if not target:
            return jsonify({"error": "No target"}), 400
        try:
            return jsonify(_get_compliance(target))
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/doctor", methods=["POST"])
    def api_doctor():
        data = request.get_json(force=True) or {}
        path = (data.get("path") or ".").strip()
        try:
            return jsonify({"results": _run_doctor(path)})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/graph", methods=["POST"])
    def api_graph():
        """Return graph data for D3 rendering."""
        data = request.get_json(force=True) or {}
        target = (data.get("target") or "").strip()
        if not target:
            return jsonify({"error": "No target"}), 400
        try:
            from agentscan.scanners.agent_scanner import scan_agent_config
            from agentscan.scanners.source_scanner import scan_source
            from agentscan.graph.engine import build_graph_from_scan

            p = Path(target)
            if p.is_dir() or (p.exists() and p.suffix == ".py"):
                result = scan_source(target)
            else:
                result = scan_agent_config(target)

            graph = build_graph_from_scan(result)
            paths = graph.find_attack_paths()

            nodes = [{"id": n.id, "label": n.label, "type": n.node_type.value if hasattr(n.node_type,"value") else str(n.node_type)} for n in graph.nodes.values()]
            edges = [{"source": e.src, "target": e.dst, "type": e.edge_type.value if hasattr(e.edge_type,"value") else str(e.edge_type)} for e in graph.edges]

            return jsonify({
                "nodes": nodes,
                "edges": edges,
                "paths": [{"id": p.id, "title": p.title, "nodes": [s.id for s in (p.steps or [])]} for p in paths],
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return app


def run_ui(port: int = 0, open_browser: bool = True):
    import socket, logging
    if port == 0:
        with socket.socket() as s:
            s.bind(("", 0))
            port = s.getsockname()[1]

    from agentscan import __version__
    app = create_app(__version__)

    url = "http://localhost:" + str(port)
    print("")
    print("  AgentScan Dashboard  " + url)
    print("  Press Ctrl+C to stop")
    print("")

    if open_browser:
        def _open():
            time.sleep(1.0)
            try:
                if sys.platform == "win32":
                    subprocess.Popen(["cmd", "/c", "start", "", url], shell=False,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                elif sys.platform == "darwin":
                    subprocess.Popen(["open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                else:
                    subprocess.Popen(["xdg-open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
        threading.Thread(target=_open, daemon=True).start()

    log = logging.getLogger("werkzeug")
    log.setLevel(logging.ERROR)
    app.run(host="localhost", port=port, debug=False, use_reloader=False)
