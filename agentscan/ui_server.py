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
                "requirement_level": c.get("requirement_level", "") if isinstance(c, dict) else getattr(c, "requirement_level", ""),
                "owner": c.get("owner", "") if isinstance(c, dict) else getattr(c, "owner", ""),
                "deadline": c.get("deadline", "") if isinstance(c, dict) else getattr(c, "deadline", ""),
                "evidence_status": c.get("evidence_status", "") if isinstance(c, dict) else getattr(c, "evidence_status", ""),
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
        out = _scan_directory(str(p))
    else:
        out = _scan_file(p)

    if "findings" in out:
        from agentscan.risk_register import annotate_findings
        out["findings"] = annotate_findings(out["findings"], target)
    return out


def _find_dependency_files(dirpath: str) -> dict:
    """
    Auto-discover dependency manifests in a directory.
    Returns dict with keys: requirements, package_json, pyproject
    """
    p = Path(dirpath)
    result = {}

    skip = {"venv", ".venv", "node_modules", "__pycache__", ".git", "site-packages"}

    def _safe_read(f: Path) -> str:
        return f.read_text(encoding="utf-8", errors="ignore")

    req_candidates = [
        f for f in p.rglob("requirements*.txt")
        if not any(part in skip for part in f.parts) and f.stat().st_size < 500_000
    ]
    if req_candidates:
        f = sorted(req_candidates, key=lambda x: (len(x.parts), str(x)))[0]
        result["requirements"] = {"path": str(f), "content": _safe_read(f)}

    pkg_candidates = [
        f for f in p.rglob("package.json")
        if not any(part in skip for part in f.parts) and f.stat().st_size < 500_000
    ]
    if pkg_candidates:
        f = sorted(pkg_candidates, key=lambda x: (len(x.parts), str(x)))[0]
        result["package_json"] = {"path": str(f), "content": _safe_read(f)}

    pyproject_candidates = [
        f for f in p.rglob("pyproject.toml")
        if not any(part in skip for part in f.parts) and f.stat().st_size < 500_000
    ]
    if pyproject_candidates:
        f = sorted(pyproject_candidates, key=lambda x: (len(x.parts), str(x)))[0]
        result["pyproject"] = {"path": str(f), "content": _safe_read(f)}

    return result


def _scan_directory(dirpath: str) -> dict:
    """
    Scan a directory using the canonical merge -- same function that feeds
    Compliance, PDF, SARIF, and Attack Graph. This is what keeps every tab
    reporting identical numbers.
    """
    result = _merge_directory_result(dirpath)
    base = _serialize_result(result)
    base["type"] = "merged"
    base["mcp_manifests_found"] = result.metadata.get("mcp_manifests_found", [])
    base["dependency_files"] = result.metadata.get("dependency_files", {})
    base["source_root"] = dirpath
    return base


def _scan_file(p: Path) -> dict:
    ext = p.suffix.lower()
    name = p.name.lower()

    if name.startswith("requirements") and ext == ".txt":
        return {**_get_supply_chain(p.read_text(encoding="utf-8", errors="ignore"), "pypi", str(p)), "type": "supply"}

    if name == "package.json":
        return {**_get_supply_chain(p.read_text(encoding="utf-8", errors="ignore"), "npm", str(p)), "type": "supply"}

    if name == "pyproject.toml":
        return {**_get_supply_chain(p.read_text(encoding="utf-8", errors="ignore"), "pyproject", str(p)), "type": "supply"}

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


def _clone_github_repo(github_url: str) -> str:
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
            raise RuntimeError("Could not clone: " + (r.stderr.strip() or "git clone failed"))
        scan_path = str(Path(tmp) / subdir) if subdir else tmp
        if not Path(scan_path).exists():
            raise FileNotFoundError("Subdirectory not found in repo: " + (subdir or ""))
        return scan_path
    except subprocess.TimeoutExpired as e:
        raise RuntimeError("Clone timed out (120s). Try a smaller repo or a specific subdirectory.") from e


def _clone_and_scan(github_url: str) -> dict:
    try:
        scan_path = _clone_github_repo(github_url)
        result = _scan_directory(scan_path)
        result["cloned_from"] = github_url
        return result
    except Exception as e:
        return {"error": str(e), "type": "unknown"}


def _build_merged_result(target: str):
    """
    THE single canonical scan function. Every consumer that needs a full
    ScanResult -- Compliance, PDF export, SARIF export, Attack Graph -- must
    call this, never call individual scanners directly. This is what keeps
    the dashboard, PDF, and graph all reporting the same numbers.

    Handles: GitHub URLs, directories (source + all MCP manifests merged),
    single .py files, single config files (agent vs MCP auto-detected),
    live MCP URLs.
    """
    from agentscan.models import ScanResult
    target = target.strip()

    if re.search(r"github[.]com/[^/]+/[^/\s]+", target):
        target = _clone_github_repo(target)

    p = Path(target)

    if target.startswith("http://") or target.startswith("https://"):
        from agentscan.scanners.mcp_scanner import scan_mcp
        return scan_mcp(target)

    if not p.exists():
        return ScanResult(target=target, scanner_type="merged",
                         error="Path not found: " + target)

    if p.is_dir():
        return _merge_directory_result(str(p))

    if p.suffix == ".py":
        from agentscan.scanners.source_scanner import scan_source
        return scan_source(target)

    if p.suffix in (".json", ".yaml", ".yml"):
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
            data = json.loads(text) if p.suffix == ".json" else __import__("yaml").safe_load(text)
            if isinstance(data, dict) and "tools" in data:
                tools = data["tools"]
                if tools and any(isinstance(t, dict) and "inputSchema" in t for t in tools[:5]):
                    from agentscan.scanners.mcp_scanner import scan_mcp
                    return scan_mcp(target)
        except Exception:
            pass
        from agentscan.scanners.agent_scanner import scan_agent_config
        return scan_agent_config(target)

    from agentscan.scanners.agent_scanner import scan_agent_config
    return scan_agent_config(target)


# Translates MCP finding tags into the capability vocabulary that
# build_graph_from_scan() understands (agent_scanner/source_scanner's
# "capabilities_detected" / "cap_to_tools" scheme). MCP scanner uses its own
# tag prefixes (MCP-SHELL, MCP-NET, etc.) which the graph engine has never
# heard of -- without this translation, MCP findings are invisible to the
# Attack Graph even when they are present in Findings/Compliance/PDF.
_MCP_TAG_TO_CAPABILITY = {
    "MCP-SHELL": "shell_exec",
    "MCP-SECRETS": "secret_access",
    "MCP-NET": "network_egress",
    "MCP-DATABASE": "database",
    "MCP-CODE-EXEC": "code_execution",
}


def _extract_tool_name(finding_title: str) -> str:
    """Pull the tool name out of a finding title like "...tool 'foo'..."."""
    if "'" in finding_title:
        parts = finding_title.split("'")
        if len(parts) >= 2:
            return parts[1]
    return finding_title


def _merge_directory_result(dirpath: str):
    """
    Run source scan + all MCP manifests in a directory, return one merged
    ScanResult. Critically, this also merges the *metadata* capability maps
    (capabilities_detected, cap_to_tools) -- not just the findings list --
    because the Attack Graph is built entirely from metadata, not findings.
    Without this, MCP findings would show up in Findings/Compliance/PDF but
    silently vanish from the Attack Graph.
    """
    from agentscan.models import ScanResult
    from agentscan.scanners.source_scanner import scan_source
    from agentscan.scanners.mcp_scanner import scan_mcp

    p = Path(dirpath)
    source_result = scan_source(dirpath)
    all_findings = list(source_result.findings or [])
    all_paths = list(source_result.attack_paths or [])
    mcp_found = []

    # Start from source scan's capability map -- we ADD to it, never replace it
    merged_caps = list(source_result.metadata.get("capabilities_detected", []) or [])
    merged_cap_to_tools = dict(source_result.metadata.get("cap_to_tools", {}) or {})

    mcp_candidates = [
        f for f in p.rglob("*.json")
        if any(kw in f.name.lower() for kw in ("mcp", "server", "manifest", "tools"))
        and f.stat().st_size < 500_000
    ]
    for mcp_file in mcp_candidates[:5]:
        try:
            text = mcp_file.read_text(encoding="utf-8", errors="ignore")
            data = json.loads(text)
            if isinstance(data, dict) and data.get("tools"):
                mcp_r = scan_mcp(str(mcp_file))
                if not mcp_r.error:
                    all_findings.extend(mcp_r.findings or [])
                    all_paths.extend(mcp_r.attack_paths or [])
                    mcp_found.append(str(mcp_file))

                    # Translate each MCP finding's tags into graph-engine capabilities
                    for f in (mcp_r.findings or []):
                        for tag in (f.tags or []):
                            cap = _MCP_TAG_TO_CAPABILITY.get(tag)
                            if cap:
                                if cap not in merged_caps:
                                    merged_caps.append(cap)
                                tool_name = _extract_tool_name(f.title)
                                merged_cap_to_tools.setdefault(cap, [])
                                if tool_name not in merged_cap_to_tools[cap]:
                                    merged_cap_to_tools[cap].append(tool_name)
        except Exception:
            pass

    meta = dict(source_result.metadata or {})
    meta["capabilities_detected"] = merged_caps
    meta["cap_to_tools"] = merged_cap_to_tools
    meta["mcp_manifests_found"] = mcp_found
    meta["dependency_files"] = _find_dependency_files(dirpath)

    return ScanResult(
        target=dirpath, scanner_type="merged",
        findings=all_findings, attack_paths=all_paths,
        metadata=meta, scan_duration_ms=source_result.scan_duration_ms,
    )


def _get_graph(target: str) -> dict:
    try:
        from agentscan.graph.engine import build_graph_from_scan
        result = _build_merged_result(target)
        if result.error:
            return {"error": result.error}
        graph = build_graph_from_scan(result)
        paths = graph.find_attack_paths()
        return _serialize_graph(graph, paths)
    except Exception as e:
        return {"error": str(e)}


def _get_compliance(target: str) -> dict:
    """Compliance mapping using the canonical merged result (same as PDF/Graph)."""
    try:
        from agentscan.compliance.framework_mapper import map_findings_to_controls
        result = _build_merged_result(target)
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
                rel = Path(name.replace("\\", "/"))
                safe_parts = [part for part in rel.parts if part not in ("", ".", "..")]
                dest = Path(tmp_dir).joinpath(*safe_parts) if safe_parts else Path(tmp_dir) / "file.txt"
                resolved = dest.resolve()
                root = Path(tmp_dir).resolve()
                if root not in resolved.parents and resolved != root:
                    continue
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

    @app.route("/api/drift/baseline", methods=["POST"])
    def api_drift_baseline():
        """Capture the current scan as the baseline for future drift comparisons."""
        from agentscan.drift import save_baseline
        data = request.get_json(force=True) or {}
        target = (data.get("target") or "").strip()
        findings = data.get("findings", [])
        if not target:
            return jsonify({"error": "target required"}), 400
        snapshot = save_baseline(target, findings)
        return jsonify({"snapshot": snapshot})

    @app.route("/api/drift/compare", methods=["POST"])
    def api_drift_compare():
        """Compare current findings against the saved baseline."""
        from agentscan.drift import compute_drift
        data = request.get_json(force=True) or {}
        target = (data.get("target") or "").strip()
        findings = data.get("findings", [])
        if not target:
            return jsonify({"error": "target required"}), 400
        return jsonify(compute_drift(target, findings))

    @app.route("/api/risk/accept", methods=["POST"])
    def api_risk_accept():
        from agentscan.risk_register import accept_risk
        data = request.get_json(force=True) or {}
        target = (data.get("target") or "").strip()
        finding_id = (data.get("finding_id") or "").strip()
        if not target or not finding_id:
            return jsonify({"error": "target and finding_id required"}), 400
        record = accept_risk(
            target=target, finding_id=finding_id,
            finding_title=data.get("finding_title", ""),
            reason=data.get("reason", ""),
            accepted_by=data.get("accepted_by", ""),
            expires=data.get("expires", ""),
        )
        return jsonify({"record": record})

    @app.route("/api/risk/revoke", methods=["POST"])
    def api_risk_revoke():
        from agentscan.risk_register import revoke_acceptance
        data = request.get_json(force=True) or {}
        target = (data.get("target") or "").strip()
        finding_id = (data.get("finding_id") or "").strip()
        revoked = revoke_acceptance(target, finding_id)
        return jsonify({"revoked": revoked})

    @app.route("/api/risk/list", methods=["POST"])
    def api_risk_list():
        from agentscan.risk_register import list_accepted_for_target
        data = request.get_json(force=True) or {}
        target = (data.get("target") or "").strip()
        return jsonify({"accepted": list_accepted_for_target(target)})

    @app.route("/api/doctor", methods=["POST"])
    def api_doctor():
        data = request.get_json(force=True) or {}
        path = (data.get("path") or ".").strip()
        return jsonify(_get_doctor(path))

    @app.route("/api/export/pdf", methods=["POST"])
    def api_export_pdf():
        """Generate a full compliance PDF using the SAME merged result as Compliance/Graph tabs."""
        import tempfile
        from flask import send_file
        data = request.get_json(force=True) or {}
        target = (data.get("target") or "").strip()
        org = data.get("organisation", "Organisation")
        agent_name = data.get("agent_name", "AI Agent")

        if not target:
            return jsonify({"error": "No target"}), 400

        try:
            result = _build_merged_result(target)
            if result.error:
                return jsonify({"error": result.error}), 400

            from agentscan.compliance.audit_report import generate_audit_report
            tmp = tempfile.mktemp(suffix=".pdf", prefix="agentscan_report_")
            generate_audit_report(
                result=result, output_path=tmp,
                agent_name=agent_name, organisation=org, include_dpia=True,
            )
            return send_file(tmp, mimetype="application/pdf", as_attachment=True,
                           download_name="agentscan_compliance_report.pdf")
        except Exception as e:
            import traceback
            return jsonify({"error": str(e), "detail": traceback.format_exc()}), 500

    @app.route("/api/export/sarif", methods=["POST"])
    def api_export_sarif():
        """Return SARIF 2.1.0 using the SAME merged result as Compliance/PDF/Graph tabs."""
        from flask import Response as FlaskResponse
        data = request.get_json(force=True) or {}
        target = (data.get("target") or "").strip()
        if not target:
            return jsonify({"error": "No target"}), 400
        try:
            result = _build_merged_result(target)
            from agentscan.outputs.json_output import to_sarif
            sarif = to_sarif(result)
            return FlaskResponse(
                json.dumps(sarif, indent=2), mimetype="application/json",
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
