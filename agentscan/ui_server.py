# -*- coding: utf-8 -*-
"""AgentScan Dashboard Backend - clean rewrite fixing all known bugs"""
from __future__ import annotations
import json, os, re, subprocess, sys, tempfile, threading, time
from pathlib import Path


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------

def _sev(x) -> str:
    return x.value if hasattr(x, "value") else str(x)

def _serialize_result(result) -> dict:
    def finding(f):
        return {
            "id": f.id, "title": f.title,
            "severity": _sev(f.severity),
            "confidence": _sev(f.confidence) if hasattr(f, "confidence") else "",
            "explanation": getattr(f, "explanation", ""),
            "impact": getattr(f, "impact", ""),
            "remediation": getattr(f, "remediation", ""),
            "mitre_atlas": list(getattr(f, "mitre_atlas", []) or []),
            "evidence": [{"source": e.source, "observed_value": str(e.observed_value)}
                         for e in (getattr(f, "evidence", []) or [])],
            "tags": list(getattr(f, "tags", []) or []),
        }
    def path(p):
        return {
            "id": p.id if hasattr(p, "id") else "",
            "title": p.title if hasattr(p, "title") else str(p),
            "severity": _sev(p.severity) if hasattr(p, "severity") else "HIGH",
            "entry_point": getattr(p, "entry_point", ""),
            "impact": getattr(p, "impact", ""),
            "description": getattr(p, "description", ""),
            "mitre_atlas": list(getattr(p, "mitre_atlas", []) or []),
            "steps": [{"id": s.id, "title": s.title,
                       "severity": _sev(s.severity)} for s in (getattr(p, "steps", []) or [])],
        }
    score = result.risk_score() if callable(getattr(result, "risk_score", None)) else 0
    counts = {}
    for f in (result.findings or []):
        s = _sev(f.severity); counts[s] = counts.get(s, 0) + 1
    return {
        "target": result.target,
        "scanner_type": result.scanner_type,
        "risk_score": score,
        "error": result.error,
        "findings": [finding(f) for f in (result.findings or [])],
        "attack_paths": [path(p) for p in (result.attack_paths or [])],
        "summary": counts,
        "metadata": result.metadata or {},
    }

def _serialize_compliance(report) -> dict:
    mappings = []
    for m in getattr(report, "mappings", []):
        controls = []
        for c in getattr(m, "controls", []):
            controls.append({
                "framework": c.get("framework", "") if isinstance(c, dict) else getattr(c, "framework", ""),
                "control_id": c.get("control_id", "") if isinstance(c, dict) else getattr(c, "control_id", ""),
                "control_name": c.get("control_name", "") if isinstance(c, dict) else getattr(c, "control_name", ""),
                "obligation": c.get("obligation", "") if isinstance(c, dict) else getattr(c, "obligation", ""),
                "how_finding_maps": c.get("how_finding_maps", "") if isinstance(c, dict) else getattr(c, "how_finding_maps", ""),
                "severity": c.get("severity", "") if isinstance(c, dict) else getattr(c, "severity", ""),
            })
        md = m if isinstance(m, dict) else vars(m)
        mappings.append({
            "finding_id": md.get("finding_id", ""),
            "finding_title": md.get("finding_title", ""),
            "finding_severity": md.get("finding_severity", ""),
            "controls": controls,
        })
    return {
        "overall_posture": getattr(report, "overall_posture", "UNKNOWN"),
        "frameworks": list(getattr(report, "frameworks_covered", []) or []),
        "priority_gaps": list(getattr(report, "priority_gaps", []) or []),
        "control_summary": dict(getattr(report, "control_summary", {}) or {}),
        "mappings": mappings,
    }

def _enum_str(v) -> str:
    """Convert enum, Node, or any object to a plain string for JSON."""
    if hasattr(v, "value"):
        return str(v.value)
    if hasattr(v, "id"):  # Node object
        return str(v.id)
    return str(v) if v is not None else ""


def _serialize_graph(graph, paths) -> dict:
    nodes = []
    for n in graph.nodes.values():
        nd = n if isinstance(n, dict) else vars(n)
        node_type = nd.get("type", "tool")
        nodes.append({
            "id": str(nd.get("id", "")),
            "label": str(nd.get("label", nd.get("id", ""))),
            "type": _enum_str(node_type),
            "is_crown_jewel": bool(nd.get("is_crown_jewel", False)),
            "attacker_controlled": bool(nd.get("attacker_controlled", False)),
        })
    edges = []
    for e in graph.edges:
        ed = e if isinstance(e, dict) else vars(e)
        edge_type = ed.get("type", "")
        src = ed.get("src", ed.get("source", ""))
        dst = ed.get("dst", ed.get("target", ""))
        edges.append({
            "source": _enum_str(src) if hasattr(src, "id") or hasattr(src, "value") else str(src),
            "target": _enum_str(dst) if hasattr(dst, "id") or hasattr(dst, "value") else str(dst),
            "type": _enum_str(edge_type),
            "label": str(ed.get("label", "")),
        })
    path_list = []
    for p in paths:
        pd = p if isinstance(p, dict) else vars(p)
        # nodes field may be Node objects, strings, or Finding objects
        raw_nodes = pd.get("nodes", [])
        if not raw_nodes:
            # Fall back to steps (Finding objects or Node objects)
            raw_nodes = pd.get("steps", [])
        node_ids = []
        for item in raw_nodes:
            if hasattr(item, "id"):
                node_ids.append(str(item.id))
            elif isinstance(item, str):
                node_ids.append(item)
        # entry_point and crown_jewel may be Node objects
        entry = pd.get("entry_point", "")
        crown = pd.get("crown_jewel", "")
        path_list.append({
            "id": str(pd.get("id", pd.get("title", ""))[:20]),
            "title": str(pd.get("title", "Attack Path")),
            "nodes": node_ids,
            "entry_point": _enum_str(entry) if hasattr(entry, "id") or hasattr(entry, "label") else str(entry),
            "crown_jewel": _enum_str(crown) if hasattr(crown, "id") or hasattr(crown, "label") else str(crown),
            "exploitability": float(pd.get("exploitability", 0) or 0),
            "impact": float(pd.get("impact", 0) or 0),
            "mitre_atlas": [str(m) for m in (pd.get("mitre_atlas", []) or [])],
        })
    return {"nodes": nodes, "edges": edges, "paths": path_list}


# ---------------------------------------------------------------------------
# Auto-scan: detects type, handles folders with mixed content
# ---------------------------------------------------------------------------

def _scan_target(target: str) -> dict:
    """Auto-detect and scan. Returns serialized result dict."""
    target = target.strip()

    # Supply chain
    for prefix in ("pypi:", "npm:", "hf:", "dataset:"):
        if target.startswith(prefix):
            from agentscan.scanners.supply_chain_scanner import scan_supply_chain
            return {**_serialize_result(scan_supply_chain(target)), "type": "supply"}

    # GitHub
    if re.search(r"github[.]com/[^/]+/[^/\s]+", target):
        return _clone_and_scan(target)

    # Live URL -> MCP
    if target.startswith("http://") or target.startswith("https://"):
        from agentscan.scanners.mcp_scanner import scan_mcp
        return {**_serialize_result(scan_mcp(target)), "type": "mcp"}

    p = Path(target)
    if not p.exists():
        return {"error": "Path not found: " + target, "type": "unknown"}

    # Directory: scan source + auto-discover MCP manifests
    if p.is_dir():
        return _scan_directory(str(p))

    # Single file
    return _scan_file(p)


def _find_dependency_files(dirpath: str) -> dict:
    """
    Auto-discover dependency manifests in a directory.
    Returns dict with keys: requirements, package_json, pyproject
    """
    p = Path(dirpath)
    result = {}
    
    for req_file in ["requirements.txt", "requirements-dev.txt", "requirements/base.txt"]:
        f = p / req_file
        if f.exists():
            result["requirements"] = {"path": str(f), "content": f.read_text(encoding="utf-8", errors="ignore")}
            break
    
    pkg_json = p / "package.json"
    if pkg_json.exists():
        result["package_json"] = {"path": str(pkg_json), "content": pkg_json.read_text(encoding="utf-8", errors="ignore")}
    
    pyproject = p / "pyproject.toml"
    if pyproject.exists():
        content = pyproject.read_text(encoding="utf-8", errors="ignore")
        # Extract dependencies from pyproject.toml
        result["pyproject"] = {"path": str(pyproject), "content": content}
    
    return result


def _scan_directory(dirpath: str) -> dict:
    """Scan a directory: source scan + auto-discover MCP manifests + dependency files."""
    from agentscan.scanners.source_scanner import scan_source
    from agentscan.scanners.mcp_scanner import scan_mcp

    p = Path(dirpath)
    result = scan_source(dirpath)
    base = _serialize_result(result)
    base["type"] = "source"

    # Auto-discover MCP manifests and merge
    mcp_candidates = [
        f for f in p.rglob("*.json")
        if any(kw in f.name.lower() for kw in ("mcp", "server", "manifest", "tools"))
        and f.stat().st_size < 500_000
    ]
    for mcp_file in mcp_candidates[:3]:
        try:
            text = mcp_file.read_text(encoding="utf-8", errors="ignore")
            data = json.loads(text)
            if isinstance(data, dict) and "tools" in data:
                mcp_result = scan_mcp(str(mcp_file))
                if not mcp_result.error:
                    mcp_dict = _serialize_result(mcp_result)
                    base["findings"] = base["findings"] + mcp_dict["findings"]
                    base["attack_paths"] = base["attack_paths"] + mcp_dict["attack_paths"]
                    base["risk_score"] = max(base.get("risk_score", 0), mcp_dict.get("risk_score", 0))
                    base["mcp_manifests_found"] = base.get("mcp_manifests_found", []) + [str(mcp_file)]
        except Exception:
            pass

    # Auto-discover dependency manifests for Supply Chain tab
    base["dependency_files"] = _find_dependency_files(dirpath)

    return base


def _scan_file(p: Path) -> dict:
    ext = p.suffix.lower()
    if ext == ".py":
        from agentscan.scanners.source_scanner import scan_source
        return {**_serialize_result(scan_source(str(p))), "type": "source"}

    if ext in (".yaml", ".yml", ".json"):
        # Sniff: MCP manifest has tools with inputSchema
        try:
            import yaml as _yaml
            text = p.read_text(encoding="utf-8", errors="ignore")
            data = _yaml.safe_load(text) if ext in (".yaml", ".yml") else json.loads(text)
            if isinstance(data, dict):
                tools = data.get("tools", [])
                if tools and any(isinstance(t, dict) and "inputSchema" in t for t in tools[:5]):
                    from agentscan.scanners.mcp_scanner import scan_mcp
                    return {**_serialize_result(scan_mcp(str(p))), "type": "mcp"}
        except Exception:
            pass
        from agentscan.scanners.agent_scanner import scan_agent_config
        return {**_serialize_result(scan_agent_config(str(p))), "type": "agent"}

    return {"error": "Unsupported file type: " + p.suffix + ". Supported: .py .yaml .yml .json", "type": "unknown"}


def _clone_and_scan(github_url: str) -> dict:
    url = github_url.strip()
    if not url.startswith("http"):
        url = "https://" + url
    subdir = None
    m = re.search(r"/tree/[^/]+/(.+)", url)
    if m:
        subdir = m.group(1)
        url = re.sub(r"/tree/.+", "", url)
    url = url.rstrip("/")
    if not url.endswith(".git"):
        url = url + ".git"

    tmp = tempfile.mkdtemp(prefix="agentscan_gh_")
    try:
        r = subprocess.run(["git", "clone", "--depth", "1", "--quiet", url, tmp],
                           capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            return {"error": "Could not clone: " + (r.stderr.strip() or "git clone failed"), "type": "unknown"}
        scan_path = str(Path(tmp) / subdir) if subdir else tmp
        if not Path(scan_path).exists():
            return {"error": "Subdirectory not found in repo: " + (subdir or ""), "type": "unknown"}
        result = _scan_directory(scan_path)
        result["cloned_from"] = github_url
        return result
    except subprocess.TimeoutExpired:
        return {"error": "Clone timed out (120s). Try a smaller repo or a specific subdirectory.", "type": "unknown"}
    except Exception as e:
        return {"error": str(e), "type": "unknown"}


def _get_graph(target: str) -> dict:
    try:
        from agentscan.graph.engine import build_graph_from_scan
        p = Path(target)
        if p.is_dir() or (p.exists() and p.suffix == ".py"):
            from agentscan.scanners.source_scanner import scan_source
            result = scan_source(target)
        else:
            from agentscan.scanners.agent_scanner import scan_agent_config
            result = scan_agent_config(target)
        graph = build_graph_from_scan(result)
        paths = graph.find_attack_paths()
        return _serialize_graph(graph, paths)
    except Exception as e:
        return {"error": str(e)}


def _get_compliance(target: str) -> dict:
    """
    Run compliance mapping including all findings (source + MCP merged).
    For directory targets: scans both .py source AND any MCP manifests found.
    """
    try:
        from agentscan.compliance.framework_mapper import map_findings_to_controls
        from agentscan.models import ScanResult

        p = Path(target)
        if p.is_dir():
            # Merged scan: source + any MCP manifests in directory
            from agentscan.scanners.source_scanner import scan_source
            from agentscan.scanners.mcp_scanner import scan_mcp
            source_result = scan_source(target)
            all_findings = list(source_result.findings or [])
            all_paths = list(source_result.attack_paths or [])

            for mcp_file in list(p.rglob("*.json"))[:5]:
                try:
                    text = mcp_file.read_text(encoding="utf-8", errors="ignore")
                    data = json.loads(text)
                    if isinstance(data, dict) and "tools" in data:
                        mcp_r = scan_mcp(str(mcp_file))
                        if not mcp_r.error:
                            all_findings.extend(mcp_r.findings or [])
                            all_paths.extend(mcp_r.attack_paths or [])
                except Exception:
                    pass

            result = ScanResult(
                target=target, scanner_type="merged",
                findings=all_findings, attack_paths=all_paths,
                metadata=source_result.metadata or {},
            )
        elif p.exists() and p.suffix == ".py":
            from agentscan.scanners.source_scanner import scan_source
            result = scan_source(target)
        elif target.startswith("http"):
            from agentscan.scanners.mcp_scanner import scan_mcp
            result = scan_mcp(target)
        elif p.exists() and p.suffix in (".json", ".yaml", ".yml"):
            # Check if MCP manifest
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")
                data = json.loads(text) if p.suffix == ".json" else {}
                if isinstance(data, dict) and "tools" in data and any(
                    "inputSchema" in t for t in data["tools"][:3] if isinstance(t, dict)
                ):
                    from agentscan.scanners.mcp_scanner import scan_mcp
                    result = scan_mcp(target)
                else:
                    from agentscan.scanners.agent_scanner import scan_agent_config
                    result = scan_agent_config(target)
            except Exception:
                from agentscan.scanners.agent_scanner import scan_agent_config
                result = scan_agent_config(target)
        else:
            from agentscan.scanners.agent_scanner import scan_agent_config
            result = scan_agent_config(target)

        if result.error:
            return {"error": result.error}

        report = map_findings_to_controls(result)
        out = _serialize_compliance(report)
        out["findings_included"] = len(result.findings or [])
        return out
    except Exception as e:
        import traceback
        return {"error": str(e), "detail": traceback.format_exc()}


def _get_supply_chain(requirements_text: str, pkg_manager: str, source_path: str = "") -> dict:
    """Parse requirements.txt / package.json / pyproject.toml and scan each dependency."""
    from agentscan.scanners.supply_chain_scanner import scan_supply_chain
    import re as _re
    packages = []
    results = []

    if pkg_manager == "pyproject":
        # Extract from [project] dependencies or [tool.poetry.dependencies]
        dep_match = _re.search(r'dependencies\s*=\s*\[(.*?)\]', requirements_text, _re.DOTALL)
        if dep_match:
            for item in _re.findall(r'"([^"]+)"', dep_match.group(1)):
                pkg = _re.split(r'[>=<!~;]', item)[0].strip()
                if pkg and pkg not in ("python",):
                    packages.append(("pypi:" + pkg, pkg))
        if not packages:
            pkg_manager = "pypi"  # fall back to line-by-line

    if pkg_manager in ("pypi", "pip"):
        for line in requirements_text.split("\n"):
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith("-") and not line.startswith("["):
                pkg = re.split(r"[>=<!~;]", line)[0].strip()
                if pkg:
                    packages.append(("pypi:" + pkg, pkg))

    elif pkg_manager == "npm":
        try:
            data = json.loads(requirements_text)
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            packages = [("npm:" + name, name) for name in list(deps.keys())[:20]]
        except Exception:
            pass

    for target, name in packages[:20]:
        try:
            r = scan_supply_chain(target)
            d = _serialize_result(r)
            d["package_name"] = name
            results.append(d)
        except Exception as e:
            results.append({"package_name": name, "error": str(e)})

    return {"packages": results, "total": len(packages), "source_path": source_path}

def _get_doctor(path: str) -> dict:
    try:
        from agentscan.doctor import run_doctor
        results = run_doctor(path)
        return {"results": [{"label": r.label, "found": r.found, "detail": r.detail,
                              "suggested_command": r.suggested_command, "severity": r.severity}
                             for r in results]}
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

def create_app(version: str = "0.2.8") -> "Flask":
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
        force_type = data.get("force_type", "")

        if force_type == "demo":
            r = subprocess.run(["agentscan", "demo"],
                capture_output=True, text=True, encoding="utf-8", timeout=120)
            return jsonify({"type": "demo", "output": r.stdout + r.stderr})

        if not target:
            return jsonify({"error": "No target provided"}), 400

        # Handle uploaded file content
        if data.get("file_content") is not None:
            return _handle_upload(data)

        try:
            return jsonify(_scan_target(target))
        except Exception as e:
            import traceback
            return jsonify({"error": str(e), "detail": traceback.format_exc()}), 500

    def _handle_upload(data: dict):
        content = data.get("file_content", "")
        filename = data.get("filename", "upload.yaml")
        suffix = Path(filename).suffix or ".yaml"
        tmp = tempfile.NamedTemporaryFile(suffix=suffix, delete=False, mode="w", encoding="utf-8")
        tmp.write(content)
        tmp.close()
        try:
            result = _scan_file(Path(tmp.name))
            result["original_filename"] = filename
            return jsonify(result)
        finally:
            try: os.unlink(tmp.name)
            except Exception: pass

    @app.route("/api/upload_dir", methods=["POST"])
    def api_upload_dir():
        """Receive multiple files as a virtual directory."""
        data = request.get_json(force=True) or {}
        files = data.get("files", [])  # [{name, content}, ...]
        if not files:
            return jsonify({"error": "No files provided"}), 400
        tmp_dir = tempfile.mkdtemp(prefix="agentscan_upload_")
        try:
            for f in files:
                name = f.get("name", "file.txt")
                content = f.get("content", "")
                dest = Path(tmp_dir) / Path(name).name
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(content, encoding="utf-8", errors="ignore")
            result = _scan_directory(tmp_dir)
            result["uploaded_files"] = len(files)
            return jsonify(result)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/compliance", methods=["POST"])
    def api_compliance():
        data = request.get_json(force=True) or {}
        target = (data.get("target") or "").strip()
        if not target:
            return jsonify({"error": "No target"}), 400
        return jsonify(_get_compliance(target))

    @app.route("/api/graph", methods=["POST"])
    def api_graph():
        data = request.get_json(force=True) or {}
        target = (data.get("target") or "").strip()
        if not target:
            return jsonify({"error": "No target"}), 400
        return jsonify(_get_graph(target))

    @app.route("/api/supply_chain", methods=["POST"])
    def api_supply_chain():
        data = request.get_json(force=True) or {}
        content = data.get("content", "")
        pkg_manager = data.get("pkg_manager", "pypi")
        target = data.get("target", "")
        folder = data.get("folder", "")  # auto-read from folder

        # Auto-read from folder if provided
        if folder and not content:
            dep_files = _find_dependency_files(folder)
            if "requirements" in dep_files:
                return jsonify(_get_supply_chain(dep_files["requirements"]["content"], "pypi",
                                                 dep_files["requirements"]["path"]))
            elif "package_json" in dep_files:
                return jsonify(_get_supply_chain(dep_files["package_json"]["content"], "npm",
                                                 dep_files["package_json"]["path"]))
            elif "pyproject" in dep_files:
                return jsonify(_get_supply_chain(dep_files["pyproject"]["content"], "pyproject",
                                                 dep_files["pyproject"]["path"]))
            return jsonify({"error": "No requirements.txt, package.json, or pyproject.toml found in " + folder,
                           "packages": [], "total": 0})

        if target and not content:
            from agentscan.scanners.supply_chain_scanner import scan_supply_chain
            result = scan_supply_chain(target)
            return jsonify({"packages": [_serialize_result(result)], "total": 1})
        return jsonify(_get_supply_chain(content, pkg_manager))

    @app.route("/api/doctor", methods=["POST"])
    def api_doctor():
        data = request.get_json(force=True) or {}
        path = (data.get("path") or ".").strip()
        return jsonify(_get_doctor(path))

    @app.route("/api/export/pdf", methods=["POST"])
    def api_export_pdf():
        """Generate a full compliance PDF report and return it as a download."""
        import tempfile, os
        from flask import send_file
        data = request.get_json(force=True) or {}
        target = (data.get("target") or "").strip()
        org = data.get("organisation", "Organisation")
        agent_name = data.get("agent_name", "AI Agent")

        if not target:
            return jsonify({"error": "No target"}), 400

        try:
            # Run scan to get ScanResult object (not dict)
            p = Path(target)
            if p.is_dir() or (p.exists() and p.suffix == ".py"):
                from agentscan.scanners.source_scanner import scan_source
                result = scan_source(target)
            elif target.startswith("http"):
                from agentscan.scanners.mcp_scanner import scan_mcp
                result = scan_mcp(target)
            else:
                from agentscan.scanners.agent_scanner import scan_agent_config
                result = scan_agent_config(target)

            if result.error:
                return jsonify({"error": result.error}), 400

            # Generate PDF
            from agentscan.compliance.audit_report import generate_audit_report
            tmp = tempfile.mktemp(suffix=".pdf", prefix="agentscan_report_")
            generate_audit_report(
                result=result,
                output_path=tmp,
                agent_name=agent_name,
                organisation=org,
                include_dpia=True,
            )

            return send_file(
                tmp,
                mimetype="application/pdf",
                as_attachment=True,
                download_name="agentscan_compliance_report.pdf",
            )
        except Exception as e:
            import traceback
            return jsonify({"error": str(e), "detail": traceback.format_exc()}), 500

    @app.route("/api/export/sarif", methods=["POST"])
    def api_export_sarif():
        """Return SARIF 2.1.0 output for GitHub Security tab integration."""
        from flask import Response as FlaskResponse
        data = request.get_json(force=True) or {}
        target = (data.get("target") or "").strip()
        if not target:
            return jsonify({"error": "No target"}), 400
        try:
            p = Path(target)
            if p.is_dir() or (p.exists() and p.suffix == ".py"):
                from agentscan.scanners.source_scanner import scan_source
                result = scan_source(target)
            else:
                from agentscan.scanners.agent_scanner import scan_agent_config
                result = scan_agent_config(target)
            from agentscan.outputs.json_output import to_sarif
            sarif = to_sarif(result)
            return FlaskResponse(
                json.dumps(sarif, indent=2),
                mimetype="application/json",
                headers={"Content-Disposition": "attachment; filename=agentscan.sarif"}
            )
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return app


def run_ui(port: int = 0, open_browser: bool = True):
    import socket, logging
    if port == 0:
        with socket.socket() as s:
            s.bind(("", 0)); port = s.getsockname()[1]
    from agentscan import __version__
    app = create_app(__version__)
    url = "http://localhost:" + str(port)
    print("\n  AgentScan Dashboard  " + url)
    print("  Press Ctrl+C to stop\n")
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
            except Exception: pass
        threading.Thread(target=_open, daemon=True).start()
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    app.run(host="localhost", port=port, debug=False, use_reloader=False)
