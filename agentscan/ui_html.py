# -*- coding: utf-8 -*-
"""
Dashboard HTML template.
Kept as a separate module so ui_server.py stays readable.
"""
from __future__ import annotations
from pathlib import Path

_ASSETS = Path(__file__).parent / "outputs" / "assets"

def _js(name: str) -> str:
    p = _ASSETS / name
    return p.read_text(encoding="utf-8") if p.exists() else ""


def get_dashboard_html(version: str = "") -> str:
    d3 = _js("d3.min.js")
    chartjs = _js("chart.umd.js")
    return _TEMPLATE.replace("__D3__", d3).replace("__CHARTJS__", chartjs).replace("__VERSION__", version)


_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AgentScan</title>
<style>
/* ─── Design tokens ─────────────────────────────────────────────── */
:root {
  --bg:        #0d1117;
  --surface:   #161b22;
  --surface2:  #1c2230;
  --border:    #30363d;
  --text:      #e6edf3;
  --muted:     #8b949e;
  --accent:    #58a6ff;
  --red:       #f85149;
  --orange:    #e3b341;
  --green:     #3fb950;
  --purple:    #bc8cff;
  --radius:    8px;
  --mono:      'Cascadia Code','Fira Code',Consolas,monospace;
  --sidebar-w: 300px;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
html, body { height: 100%; }
body {
  background: var(--bg); color: var(--text);
  font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;
  font-size: 14px; line-height: 1.5;
  display: flex; flex-direction: column; overflow: hidden;
}

/* ─── Top bar ───────────────────────────────────────────────────── */
.topbar {
  display: flex; align-items: center; gap: 12px;
  padding: 0 20px; height: 48px;
  background: var(--surface); border-bottom: 1px solid var(--border);
  flex-shrink: 0; z-index: 10;
}
.logo { font-size: 16px; font-weight: 700; color: var(--accent); letter-spacing: -.3px; }
.logo-sub { font-size: 11px; color: var(--muted); }
.topbar-sep { flex: 1; }
.version-badge {
  font-size: 11px; font-family: var(--mono); color: var(--muted);
  background: var(--border); padding: 2px 8px; border-radius: 20px;
}

/* ─── Main layout ───────────────────────────────────────────────── */
.layout { display: flex; flex: 1; overflow: hidden; }

/* ─── Left sidebar ──────────────────────────────────────────────── */
.sidebar {
  width: var(--sidebar-w); flex-shrink: 0;
  background: var(--surface); border-right: 1px solid var(--border);
  display: flex; flex-direction: column; overflow-y: auto;
}
.sidebar-block { padding: 16px; border-bottom: 1px solid var(--border); }
.sidebar-label {
  font-size: 10px; font-weight: 700; color: var(--muted);
  text-transform: uppercase; letter-spacing: .6px; margin-bottom: 10px;
}

/* ─── Drop zone ─────────────────────────────────────────────────── */
.drop-zone {
  border: 2px dashed var(--border); border-radius: var(--radius);
  padding: 20px 14px; text-align: center; cursor: pointer;
  transition: border-color .15s, background .15s; margin-bottom: 10px;
}
.drop-zone:hover, .drop-zone.drag-over {
  border-color: var(--accent); background: rgba(88,166,255,.05);
}
.drop-icon { font-size: 28px; margin-bottom: 6px; }
.drop-title { font-size: 13px; font-weight: 600; margin-bottom: 4px; }
.drop-hint { font-size: 11px; color: var(--muted); line-height: 1.5; }

.path-row {
  display: flex; gap: 6px; align-items: center; margin-bottom: 8px;
}
.path-input {
  flex: 1; background: var(--bg); border: 1px solid var(--border);
  border-radius: 6px; color: var(--text); font-family: var(--mono);
  font-size: 11px; padding: 7px 9px; outline: none;
}
.path-input:focus { border-color: var(--accent); }
.path-input::placeholder { color: var(--muted); }
.icon-btn {
  background: var(--border); border: none; color: var(--muted);
  border-radius: 6px; width: 30px; height: 30px; cursor: pointer;
  font-size: 14px; display: flex; align-items: center; justify-content: center;
}
.icon-btn:hover { background: var(--accent); color: #0d1117; }

/* Package search (supply chain) */
.pkg-section { margin-bottom: 8px; }
.pkg-tabs {
  display: flex; gap: 4px; margin-bottom: 8px;
}
.pkg-tab {
  font-size: 11px; padding: 3px 10px; border-radius: 20px;
  border: 1px solid var(--border); background: transparent;
  color: var(--muted); cursor: pointer;
}
.pkg-tab.active { border-color: var(--accent); color: var(--accent); background: rgba(88,166,255,.1); }

/* Scan button */
.scan-btn {
  width: 100%; padding: 10px; font-size: 14px; font-weight: 700;
  background: var(--accent); color: #0d1117; border: none;
  border-radius: var(--radius); cursor: pointer; transition: opacity .15s;
}
.scan-btn:hover { opacity: .88; }
.scan-btn:disabled { opacity: .4; cursor: not-allowed; }

/* Type auto-detected badge */
.detected-badge {
  display: inline-flex; align-items: center; gap: 5px;
  font-size: 11px; color: var(--green); margin-bottom: 8px;
}
.detected-badge::before { content: ''; width: 6px; height: 6px; border-radius: 50%; background: var(--green); }

/* History */
.history-item {
  display: flex; align-items: center; gap: 8px; padding: 6px 8px;
  border-radius: 6px; cursor: pointer; transition: background .1s;
}
.history-item:hover { background: var(--bg); }
.h-dot { width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; }
.h-path { flex: 1; font-size: 11px; font-family: var(--mono); color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.h-time { font-size: 10px; color: var(--muted); flex-shrink: 0; }
.h-diff { font-size: 10px; color: var(--orange); flex-shrink: 0; }

/* ─── Content area ──────────────────────────────────────────────── */
.content { flex: 1; overflow-y: auto; }

/* ─── Welcome ───────────────────────────────────────────────────── */
.welcome { max-width: 620px; margin: 60px auto; padding: 0 24px; text-align: center; }
.welcome-icon { font-size: 52px; margin-bottom: 16px; }
.welcome h2 { font-size: 22px; font-weight: 700; margin-bottom: 10px; }
.welcome p { color: var(--muted); margin-bottom: 28px; line-height: 1.7; }
.welcome-cards {
  display: grid; grid-template-columns: repeat(3,1fr); gap: 10px; text-align: left;
}
.wcard {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 14px;
}
.wcard-n { font-size: 10px; color: var(--accent); font-weight: 700; margin-bottom: 6px; }
.wcard-t { font-size: 12px; font-weight: 600; margin-bottom: 4px; }
.wcard-d { font-size: 11px; color: var(--muted); line-height: 1.5; }

/* ─── Results tabs ──────────────────────────────────────────────── */
.results-wrap { padding: 20px 24px; }
.result-header { display: flex; align-items: center; gap: 12px; margin-bottom: 20px; flex-wrap: wrap; }
.result-target { font-family: var(--mono); font-size: 12px; color: var(--muted); flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.result-type-badge { font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 4px; background: rgba(88,166,255,.1); color: var(--accent); text-transform: uppercase; flex-shrink: 0; }
.action-btns { display: flex; gap: 6px; flex-shrink: 0; }
.btn-sm { padding: 5px 12px; border-radius: 6px; border: 1px solid var(--border); background: transparent; color: var(--muted); font-size: 11px; cursor: pointer; transition: all .15s; }
.btn-sm:hover { border-color: var(--accent); color: var(--accent); }

.tabs { display: flex; gap: 2px; margin-bottom: 20px; border-bottom: 1px solid var(--border); }
.tab {
  padding: 8px 14px; font-size: 13px; color: var(--muted); cursor: pointer;
  border-bottom: 2px solid transparent; margin-bottom: -1px; transition: all .15s;
}
.tab.active { color: var(--accent); border-bottom-color: var(--accent); }
.tab:hover:not(.active) { color: var(--text); }
.tab-badge { font-size: 10px; font-weight: 700; padding: 1px 6px; border-radius: 20px; background: var(--border); color: var(--muted); margin-left: 5px; }
.tab.active .tab-badge { background: rgba(88,166,255,.15); color: var(--accent); }

/* ─── Summary tab ───────────────────────────────────────────────── */
.metrics { display: grid; grid-template-columns: repeat(4,1fr); gap: 12px; margin-bottom: 20px; }
.metric {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 16px;
}
.metric-lbl { font-size: 10px; color: var(--muted); text-transform: uppercase; letter-spacing: .4px; margin-bottom: 6px; }
.metric-val { font-size: 30px; font-weight: 700; line-height: 1; }
.metric-sub { font-size: 11px; color: var(--muted); margin-top: 4px; }
.risk-bar { height: 4px; background: var(--border); border-radius: 2px; margin-top: 10px; overflow: hidden; }
.risk-fill { height: 100%; border-radius: 2px; transition: width .8s ease; }

.severity-strip { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 20px; }
.sev-pill {
  display: flex; align-items: center; gap: 6px; padding: 6px 12px;
  border-radius: 6px; font-size: 12px; font-weight: 600; border: 1px solid;
}
.sev-CRITICAL { background: rgba(248,81,73,.1); color: var(--red); border-color: rgba(248,81,73,.3); }
.sev-HIGH     { background: rgba(227,179,65,.1); color: var(--orange); border-color: rgba(227,179,65,.3); }
.sev-MEDIUM   { background: rgba(227,179,65,.06); color: var(--orange); border-color: rgba(227,179,65,.2); }
.sev-LOW      { background: rgba(88,166,255,.08); color: var(--accent); border-color: rgba(88,166,255,.2); }
.sev-INFO     { background: var(--border); color: var(--muted); border-color: var(--border); }
.sev-count { font-size: 16px; }

/* Compliance posture */
.posture-card {
  border: 1px solid var(--border); border-radius: var(--radius);
  padding: 16px 20px; margin-bottom: 20px; display: flex; align-items: center; gap: 16px;
}
.posture-label { font-size: 11px; color: var(--muted); margin-bottom: 4px; }
.posture-value { font-size: 20px; font-weight: 700; }
.posture-COMPLIANT { color: var(--green); }
.posture-NON-COMPLIANT { color: var(--red); }
.posture-UNKNOWN { color: var(--muted); }
.posture-sep { width: 1px; background: var(--border); align-self: stretch; }
.frameworks-list { display: flex; gap: 6px; flex-wrap: wrap; }
.fw-chip {
  font-size: 10px; padding: 2px 8px; border-radius: 4px;
  background: rgba(188,140,255,.1); color: var(--purple); border: 1px solid rgba(188,140,255,.2);
}

/* ─── Graph tab ─────────────────────────────────────────────────── */
.graph-container {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: var(--radius); height: 480px; position: relative; overflow: hidden;
  margin-bottom: 16px;
}
#graph-svg { width: 100%; height: 100%; }
.graph-legend {
  display: flex; gap: 16px; flex-wrap: wrap; font-size: 11px; color: var(--muted);
  margin-bottom: 16px;
}
.legend-item { display: flex; align-items: center; gap: 5px; }
.legend-dot { width: 10px; height: 10px; border-radius: 50%; }
.graph-paths { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
.path-card {
  background: var(--surface); border: 1px solid var(--border);
  border-left: 3px solid var(--red); border-radius: var(--radius);
  padding: 12px 14px; cursor: pointer; transition: background .15s;
}
.path-card:hover { background: var(--surface2); }
.path-card.selected { border-left-color: var(--accent); background: rgba(88,166,255,.04); }
.path-title { font-size: 12px; font-weight: 600; margin-bottom: 5px; }
.path-chain { font-family: var(--mono); font-size: 10px; color: var(--accent); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.path-entry { font-size: 10px; color: var(--muted); margin-top: 4px; }

/* ─── Findings tab ──────────────────────────────────────────────── */
.filter-bar { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 14px; align-items: center; }
.filter-chip {
  padding: 4px 12px; border-radius: 20px; border: 1px solid var(--border);
  background: transparent; color: var(--muted); font-size: 11px; cursor: pointer;
}
.filter-chip.active { border-color: var(--accent); color: var(--accent); background: rgba(88,166,255,.1); }
.filter-chip:hover:not(.active) { border-color: var(--muted); }

.finding-card {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: var(--radius); margin-bottom: 8px; overflow: hidden;
}
.finding-head {
  display: flex; align-items: center; gap: 10px; padding: 11px 14px;
  cursor: pointer;
}
.finding-head:hover { background: rgba(255,255,255,.02); }
.sev-chip {
  font-size: 10px; font-weight: 700; padding: 2px 7px; border-radius: 4px;
  letter-spacing: .3px; flex-shrink: 0;
}
.finding-title-text { flex: 1; font-size: 13px; min-width: 0; }
.chevron { color: var(--muted); font-size: 11px; flex-shrink: 0; transition: transform .2s; }
.finding-card.open .chevron { transform: rotate(90deg); }
.finding-body { display: none; padding: 0 14px 14px; }
.finding-card.open .finding-body { display: block; }
.f-section { margin-top: 10px; }
.f-label { font-size: 10px; color: var(--muted); text-transform: uppercase; letter-spacing: .4px; margin-bottom: 3px; }
.f-text { font-size: 12px; line-height: 1.6; }
.f-fix { background: rgba(63,185,80,.06); border: 1px solid rgba(63,185,80,.2); border-radius: 6px; padding: 8px 10px; font-size: 12px; color: var(--green); margin-top: 10px; }
.f-evidence { background: var(--bg); border-radius: 6px; padding: 8px 10px; font-family: var(--mono); font-size: 11px; color: var(--muted); margin-top: 8px; line-height: 1.7; }
.mitre-tags { display: flex; gap: 5px; flex-wrap: wrap; margin-top: 8px; }
.mitre-tag { background: rgba(188,140,255,.1); color: var(--purple); border-radius: 4px; padding: 2px 6px; font-size: 10px; font-family: var(--mono); }

/* ─── Compliance tab ────────────────────────────────────────────── */
.compliance-section { margin-bottom: 20px; }
.priority-action {
  background: rgba(248,81,73,.06); border: 1px solid rgba(248,81,73,.2);
  border-radius: 6px; padding: 10px 14px; margin-bottom: 8px; font-size: 12px; line-height: 1.6;
}
.control-table { width: 100%; border-collapse: collapse; font-size: 12px; }
.control-table th { text-align: left; padding: 8px 12px; font-size: 10px; text-transform: uppercase; color: var(--muted); border-bottom: 1px solid var(--border); }
.control-table td { padding: 8px 12px; border-bottom: 1px solid rgba(48,54,61,.5); vertical-align: top; }
.control-table tr:hover td { background: rgba(255,255,255,.02); }

/* ─── Loading / error ───────────────────────────────────────────── */
.center-box { display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 300px; gap: 14px; }
.spinner { width: 36px; height: 36px; border: 3px solid var(--border); border-top-color: var(--accent); border-radius: 50%; animation: spin .7s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
.loading-msg { color: var(--muted); font-size: 13px; }
.error-card { max-width: 560px; background: rgba(248,81,73,.08); border: 1px solid rgba(248,81,73,.3); border-radius: var(--radius); padding: 16px 20px; margin: 40px auto; }
.error-title { font-weight: 700; color: var(--red); margin-bottom: 8px; }
.error-body { font-size: 12px; line-height: 1.7; white-space: pre-wrap; word-break: break-word; font-family: var(--mono); }

/* ─── Demo output ───────────────────────────────────────────────── */
.demo-out { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 16px; font-family: var(--mono); font-size: 12px; line-height: 1.8; overflow-x: auto; }

/* ─── Scrollbar ─────────────────────────────────────────────────── */
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
</style>
</head>
<body>

<!-- Top bar -->
<div class="topbar">
  <div class="logo">AgentScan</div>
  <div class="logo-sub">AI Agent Security</div>
  <div class="topbar-sep"></div>
  <div class="version-badge">v__VERSION__</div>
</div>

<div class="layout">

  <!-- ── Sidebar ─────────────────────────────────────────────────── -->
  <div class="sidebar">

    <!-- Universal drop zone -->
    <div class="sidebar-block">
      <div class="sidebar-label">Scan anything</div>

      <div class="drop-zone" id="drop-zone"
           onclick="document.getElementById('file-picker').click()"
           ondragover="ev.preventDefault();ev.dataTransfer.dropEffect='copy';this.classList.add('drag-over')"
           ondragleave="this.classList.remove('drag-over')"
           ondrop="handleDrop(event)">
        <div class="drop-icon">&#128194;</div>
        <div class="drop-title">Drop a file or folder</div>
        <div class="drop-hint">Python files, YAML/JSON configs,<br>MCP manifests — auto-detected</div>
      </div>
      <input type="file" id="file-picker" style="display:none" multiple onchange="handleFilePick(event)">

      <div class="path-row">
        <input class="path-input" id="path-input" placeholder="Paste a path or URL..."
               oninput="onPathChange()" onkeydown="if(event.key==='Enter') runScan()">
        <button class="icon-btn" title="Paste from clipboard" onclick="pasteClip()">&#128203;</button>
      </div>

      <div class="detected-badge" id="detected-badge" style="display:none">
        Auto-detected: <span id="detected-type"></span>
      </div>

      <!-- Package search -->
      <div class="pkg-section">
        <div class="sidebar-label" style="margin-bottom:6px">Or scan a package</div>
        <div class="pkg-tabs">
          <button class="pkg-tab active" onclick="setPkgType(this,'pypi')">PyPI</button>
          <button class="pkg-tab" onclick="setPkgType(this,'npm')">npm</button>
          <button class="pkg-tab" onclick="setPkgType(this,'hf')">HuggingFace</button>
          <button class="pkg-tab" onclick="setPkgType(this,'dataset')">Dataset</button>
        </div>
        <div class="path-row">
          <input class="path-input" id="pkg-input" placeholder="e.g. langchain"
                 onkeydown="if(event.key==='Enter') runPkgScan()">
          <button class="icon-btn" onclick="runPkgScan()">&#8594;</button>
        </div>
      </div>

      <button class="scan-btn" id="scan-btn" onclick="runScan()">Scan</button>
      <div style="margin-top:8px;text-align:center">
        <button class="btn-sm" onclick="runDemo()" style="font-size:11px;width:100%">Run built-in demo (12 scenarios)</button>
      </div>
    </div>

    <!-- History -->
    <div class="sidebar-block" style="flex:1">
      <div class="sidebar-label">Scan history</div>
      <div id="history-list"><div style="font-size:11px;color:var(--muted);text-align:center;padding:14px 0">No scans yet</div></div>
    </div>

  </div>

  <!-- ── Content ─────────────────────────────────────────────────── -->
  <div class="content" id="content">
    <div class="welcome">
      <div class="welcome-icon">&#128737;</div>
      <h2>Find the attack path before an attacker does</h2>
      <p>Drop a file, paste a path, or search a package.<br>
         AgentScan auto-detects the type and shows the complete attack chain.</p>
      <div class="welcome-cards">
        <div class="wcard">
          <div class="wcard-n">Source code</div>
          <div class="wcard-t">Python agents</div>
          <div class="wcard-d">LangChain, CrewAI, AutoGen, PydanticAI, LlamaIndex, 12 more</div>
        </div>
        <div class="wcard">
          <div class="wcard-n">Config files</div>
          <div class="wcard-t">YAML / JSON / No-code</div>
          <div class="wcard-d">Agent configs, Dify, n8n, Flowise, MCP server manifests</div>
        </div>
        <div class="wcard">
          <div class="wcard-n">Supply chain</div>
          <div class="wcard-t">Packages & models</div>
          <div class="wcard-d">PyPI, npm, HuggingFace models, datasets</div>
        </div>
      </div>
    </div>
  </div>

</div>

<script>__D3__</script>
<script>__CHARTJS__</script>
<script>
// ─── State ──────────────────────────────────────────────────────────
let scanHistory = JSON.parse(localStorage.getItem('agentscan_history') || '[]');
let currentResult = null;
let currentTarget = null;
let currentTab = 'summary';
let pkgType = 'pypi';
let graphData = null;

// ─── Utilities ──────────────────────────────────────────────────────
const esc = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const riskColor = s => s>=70?'var(--red)':s>=40?'var(--orange)':s>=10?'#e3b341':'var(--green)';
const riskLabel = s => s>=70?'CRITICAL':s>=40?'HIGH':s>=10?'MEDIUM':'LOW';
const dotColor = s => s>=70?'#f85149':s>=40?'#e3b341':s>=10?'#e3b341':'#3fb950';

function showContent(html) { document.getElementById('content').innerHTML = html; }
function showLoading(msg) {
  showContent('<div class="center-box"><div class="spinner"></div><div class="loading-msg">'+esc(msg||'Scanning...')+'</div></div>');
}
function showError(msg) {
  showContent('<div class="error-card"><div class="error-title">Error</div><div class="error-body">'+esc(msg)+'</div></div>');
}

// ─── Drop / paste / file pick ───────────────────────────────────────
function handleDrop(ev) {
  ev.preventDefault();
  document.getElementById('drop-zone').classList.remove('drag-over');
  const items = ev.dataTransfer.items;
  if (!items || !items.length) return;
  const entry = items[0].webkitGetAsEntry ? items[0].webkitGetAsEntry() : null;
  if (entry) {
    document.getElementById('path-input').value = entry.fullPath || entry.name;
    onPathChange();
  } else if (ev.dataTransfer.files.length) {
    document.getElementById('path-input').value = ev.dataTransfer.files[0].name;
    onPathChange();
  }
}

function handleFilePick(ev) {
  const f = ev.target.files[0];
  if (f) { document.getElementById('path-input').value = f.name; onPathChange(); }
}

async function pasteClip() {
  try {
    const t = await navigator.clipboard.readText();
    document.getElementById('path-input').value = t.trim();
    onPathChange();
  } catch(e) { alert('Paste with Ctrl+V into the path box'); }
}

// ─── Auto-detect input type ─────────────────────────────────────────
function onPathChange() {
  const val = document.getElementById('path-input').value.trim();
  const badge = document.getElementById('detected-badge');
  const typeSpan = document.getElementById('detected-type');
  if (!val) { badge.style.display = 'none'; return; }
  let detected = '';
  if (val.startsWith('pypi:') || val.startsWith('npm:') || val.startsWith('hf:') || val.startsWith('dataset:')) detected = 'Supply chain package';
  else if (val.startsWith('http')) detected = 'MCP server (live URL)';
  else if (val.endsWith('.py')) detected = 'Python source file';
  else if (val.endsWith('.yaml') || val.endsWith('.yml') || val.endsWith('.json')) detected = 'Agent config / manifest';
  else if (!val.includes('.')) detected = 'Directory (source scan)';
  if (detected) { typeSpan.textContent = detected; badge.style.display = 'inline-flex'; }
  else { badge.style.display = 'none'; }
}

function setPkgType(btn, type) {
  document.querySelectorAll('.pkg-tab').forEach(t => t.classList.remove('active'));
  btn.classList.add('active');
  pkgType = type;
  const hints = { pypi: 'e.g. langchain', npm: 'e.g. @langchain/core', hf: 'e.g. microsoft/phi-3', dataset: 'e.g. openai/gsm8k' };
  document.getElementById('pkg-input').placeholder = hints[type] || 'package name';
}

// ─── Scan ────────────────────────────────────────────────────────────
async function runScan() {
  const target = document.getElementById('path-input').value.trim();
  if (!target) { showError('Please enter a path, URL, or package identifier'); return; }
  await _scan(target);
}

async function runPkgScan() {
  const pkg = document.getElementById('pkg-input').value.trim();
  if (!pkg) return;
  const target = pkgType + ':' + pkg;
  document.getElementById('path-input').value = target;
  await _scan(target);
}

async function runDemo() {
  showLoading('Running 12 built-in attack scenarios...');
  setBtnState(true);
  try {
    const r = await fetch('/api/scan', { method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ target: '__demo__', force_type: 'demo' }) });
    const d = await r.json();
    renderDemo(d.output || d.error || 'No output');
  } catch(e) { showError(e.message); }
  finally { setBtnState(false); }
}

async function _scan(target) {
  showLoading('Scanning ' + target + '...');
  setBtnState(true);
  try {
    const r = await fetch('/api/scan', { method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ target }) });
    const d = await r.json();
    if (d.error) { showError(d.error + (d.detail ? '\n\n' + d.detail : '')); return; }
    currentResult = d;
    currentTarget = target;
    addHistory(target, d.risk_score||0, d.type||d.scanner_type);
    renderResults(d, target);
    // Kick off graph load in background
    loadGraph(target);
    // Kick off compliance load in background
    loadCompliance(target);
  } catch(e) { showError(e.message); }
  finally { setBtnState(false); }
}

function setBtnState(disabled) {
  const btn = document.getElementById('scan-btn');
  btn.disabled = disabled;
  btn.textContent = disabled ? 'Scanning...' : 'Scan';
}

// ─── History ─────────────────────────────────────────────────────────
function addHistory(target, score, type) {
  const now = new Date();
  const prev = scanHistory.find(h => h.target === target);
  const diff = prev ? score - prev.score : null;
  scanHistory = scanHistory.filter(h => h.target !== target);
  scanHistory.unshift({ target, score, type, time: now.toLocaleTimeString(), diff });
  if (scanHistory.length > 20) scanHistory.pop();
  localStorage.setItem('agentscan_history', JSON.stringify(scanHistory));
  renderHistory();
}

function renderHistory() {
  const el = document.getElementById('history-list');
  if (!scanHistory.length) { el.innerHTML = '<div style="font-size:11px;color:var(--muted);text-align:center;padding:14px 0">No scans yet</div>'; return; }
  el.innerHTML = scanHistory.map((h,i) => {
    let diffHtml = '';
    if (h.diff !== null && h.diff !== 0) {
      const sign = h.diff > 0 ? '+' : '';
      diffHtml = '<div class="h-diff">' + sign + h.diff + '</div>';
    }
    return '<div class="history-item" onclick="replayScan(' + i + ')" title="' + esc(h.target) + '">' +
      '<div class="h-dot" style="background:' + dotColor(h.score) + '"></div>' +
      '<div class="h-path">' + esc(h.target.split(/[\\/]/).pop() || h.target) + '</div>' +
      '<div class="h-time">' + h.time + '</div>' +
      diffHtml +
      '</div>';
  }).join('');
}

async function replayScan(i) {
  const h = scanHistory[i];
  if (!h) return;
  document.getElementById('path-input').value = h.target;
  onPathChange();
  await _scan(h.target);
}

// ─── Render results ──────────────────────────────────────────────────
function renderResults(d, target) {
  const score = d.risk_score || 0;
  const findings = d.findings || [];
  const paths = d.attack_paths || [];
  const reportable = findings.filter(f => f.severity !== 'INFO');
  const counts = { CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0, INFO:0 };
  findings.forEach(f => { if (counts[f.severity]!==undefined) counts[f.severity]++; });
  const typeLabel = (d.type||d.scanner_type||'').replace('_scanner','').replace('_',' ');

  let html = '<div class="results-wrap">';
  html += '<div class="result-header">';
  html += '<div class="result-target">' + esc(target) + '</div>';
  html += '<div class="result-type-badge">' + esc(typeLabel) + '</div>';
  html += '<div class="action-btns">';
  html += '<button class="btn-sm" onclick="copyJSON()">Copy JSON</button>';
  html += '<button class="btn-sm" onclick="copyMarkdown()">Copy MD</button>';
  html += '</div></div>';

  // Tabs
  const tabCount = (label, count) => '<span class="tab-badge">' + count + '</span>';
  html += '<div class="tabs">';
  html += '<div class="tab active" data-tab="summary" onclick="switchTab(this,\'summary\')">Summary</div>';
  html += '<div class="tab" data-tab="graph" onclick="switchTab(this,\'graph\')">Attack Graph' + tabCount('paths', paths.length) + '</div>';
  html += '<div class="tab" data-tab="findings" onclick="switchTab(this,\'findings\')">Findings' + tabCount('findings', reportable.length) + '</div>';
  html += '<div class="tab" data-tab="compliance" onclick="switchTab(this,\'compliance\')">Compliance</div>';
  html += '</div>';

  // ── Summary tab ──
  html += '<div id="tab-summary" class="tab-pane">';

  // Metrics row
  html += '<div class="metrics">';
  html += '<div class="metric"><div class="metric-lbl">Risk Score</div>';
  html += '<div class="metric-val" style="color:' + riskColor(score) + '">' + score + '<span style="font-size:14px;color:var(--muted)">/100</span></div>';
  html += '<div class="metric-sub">' + riskLabel(score) + '</div>';
  html += '<div class="risk-bar"><div class="risk-fill" id="risk-fill" style="width:0%;background:' + riskColor(score) + '"></div></div></div>';

  html += '<div class="metric"><div class="metric-lbl">Critical</div><div class="metric-val" style="color:var(--red)">' + counts.CRITICAL + '</div><div class="metric-sub">' + counts.HIGH + ' high</div></div>';
  html += '<div class="metric"><div class="metric-lbl">Attack Paths</div><div class="metric-val" style="color:' + (paths.length?'var(--red)':'var(--green)') + '">' + paths.length + '</div><div class="metric-sub">complete chains</div></div>';
  html += '<div class="metric"><div class="metric-lbl">Total Findings</div><div class="metric-val">' + reportable.length + '</div><div class="metric-sub">' + counts.MEDIUM + ' med  ' + counts.LOW + ' low</div></div>';
  html += '</div>';

  // Severity strip
  html += '<div class="severity-strip">';
  ['CRITICAL','HIGH','MEDIUM','LOW','INFO'].forEach(s => {
    if (counts[s] > 0)
      html += '<div class="sev-pill sev-' + s + '"><span class="sev-count">' + counts[s] + '</span>' + s + '</div>';
  });
  html += '</div>';

  // Compliance posture placeholder (filled by loadCompliance)
  html += '<div class="posture-card" id="posture-card"><div style="color:var(--muted);font-size:12px">Loading compliance posture...</div></div>';

  // Key attack paths preview
  if (paths.length) {
    html += '<div style="font-size:12px;font-weight:600;color:var(--muted);margin-bottom:10px;text-transform:uppercase;letter-spacing:.5px">Top Attack Paths</div>';
    paths.slice(0,3).forEach(p => {
      const steps = (p.steps||[]).slice(0,4).map(s => s.title ? (s.title.includes("'")?s.title.split("'")[1]:s.title.substring(0,20)) : '').filter(Boolean);
      html += '<div class="path-card" onclick="switchTab(document.querySelector(\'[data-tab=graph]\'),\'graph\')" style="margin-bottom:8px">';
      html += '<div class="path-title">' + esc(p.title) + '</div>';
      if (steps.length) html += '<div class="path-chain">Prompt -&gt; ' + steps.map(esc).join(' -&gt; ') + '</div>';
      html += '<div class="path-entry">Entry: ' + esc(p.entry_point||'') + ' &nbsp; ' + (p.mitre_atlas||[]).join(', ') + '</div>';
      html += '</div>';
    });
  }
  html += '</div>'; // end summary tab

  // ── Graph tab (container only, filled by loadGraph) ──
  html += '<div id="tab-graph" class="tab-pane" style="display:none">';
  html += '<div class="graph-container"><svg id="graph-svg"><text x="50%" y="50%" fill="#8b949e" font-size="13" text-anchor="middle" dominant-baseline="middle">Loading graph...</text></svg></div>';
  html += '<div class="graph-legend">';
  const legendItems = [['#f85149','Entry Point / Crown Jewel'],['#bc8cff','Agent / MCP Server'],['#58a6ff','Tool'],['#e3b341','Resource / Data'],['#3fb950','External Network']];
  legendItems.forEach(([c,l]) => html += '<div class="legend-item"><div class="legend-dot" style="background:' + c + '"></div>' + esc(l) + '</div>');
  html += '</div>';
  html += '<div class="graph-paths" id="graph-paths-list"></div>';
  html += '</div>';

  // ── Findings tab ──
  html += '<div id="tab-findings" class="tab-pane" style="display:none">';
  if (!reportable.length) {
    html += '<div class="center-box" style="min-height:200px"><div style="color:var(--green);font-size:14px">No reportable findings</div></div>';
  } else {
    html += '<div class="filter-bar">';
    html += '<button class="filter-chip active" onclick="filterFindings(this,\'ALL\')">All (' + reportable.length + ')</button>';
    ['CRITICAL','HIGH','MEDIUM','LOW'].forEach(s => { if (counts[s]) html += '<button class="filter-chip" onclick="filterFindings(this,\'' + s + '\')">' + s + ' (' + counts[s] + ')</button>'; });
    html += '</div><div id="findings-list">';
    reportable.forEach((f,i) => {
      html += '<div class="finding-card" data-sev="' + f.severity + '" id="fc' + i + '">';
      html += '<div class="finding-head" onclick="toggleF(' + i + ')">';
      html += '<span class="sev-chip sev-' + f.severity + '">' + f.severity + '</span>';
      html += '<span class="finding-title-text">' + esc(f.title) + '</span>';
      html += '<span class="chevron">&#9654;</span></div>';
      html += '<div class="finding-body">';
      if (f.explanation) html += '<div class="f-section"><div class="f-label">What is happening</div><div class="f-text">' + esc(f.explanation) + '</div></div>';
      if (f.impact) html += '<div class="f-section"><div class="f-label">Impact</div><div class="f-text">' + esc(f.impact) + '</div></div>';
      if (f.remediation) html += '<div class="f-fix"><strong>Fix: </strong>' + esc(f.remediation) + '</div>';
      if (f.evidence && f.evidence.length) html += '<div class="f-evidence">' + f.evidence.map(e => esc(e.source + ': ' + e.observed_value)).join('<br>') + '</div>';
      if (f.mitre_atlas && f.mitre_atlas.length) html += '<div class="mitre-tags">' + f.mitre_atlas.map(m => '<span class="mitre-tag">' + m + '</span>').join('') + '</div>';
      html += '</div></div>';
    });
    html += '</div>';
  }
  html += '</div>';

  // ── Compliance tab (filled by loadCompliance) ──
  html += '<div id="tab-compliance" class="tab-pane" style="display:none">';
  html += '<div id="compliance-content"><div class="center-box" style="min-height:200px"><div class="spinner"></div><div class="loading-msg">Loading compliance map...</div></div></div>';
  html += '</div>';

  html += '</div>'; // results-wrap
  showContent(html);

  // Animate risk bar
  setTimeout(() => {
    const el = document.getElementById('risk-fill');
    if (el) el.style.width = score + '%';
  }, 100);

  renderHistory();
}

// ─── Tab switching ────────────────────────────────────────────────────
function switchTab(btn, tabId) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-pane').forEach(t => t.style.display = 'none');
  btn.classList.add('active');
  const pane = document.getElementById('tab-' + tabId);
  if (pane) pane.style.display = '';
  currentTab = tabId;
  if (tabId === 'graph' && graphData) renderGraph(graphData);
}

// ─── Graph rendering ──────────────────────────────────────────────────
async function loadGraph(target) {
  try {
    const r = await fetch('/api/graph', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({target}) });
    const d = await r.json();
    if (!d.error) { graphData = d; if (currentTab === 'graph') renderGraph(d); }
  } catch(e) {}
}

function renderGraph(data) {
  const svg = document.getElementById('graph-svg');
  if (!svg || !data) return;
  const W = svg.clientWidth || 800;
  const H = svg.clientHeight || 480;
  svg.innerHTML = '';

  const nodeColors = {
    entry_point: '#f85149', crown_jewel: '#f85149',
    agent: '#bc8cff', mcp_server: '#bc8cff',
    tool: '#58a6ff',
    resource: '#e3b341', data_store: '#e3b341',
    network: '#3fb950', external: '#3fb950',
  };
  const getColor = type => nodeColors[type] || '#8b949e';

  const nodes = data.nodes.map(n => ({...n}));
  const links = data.edges.map(e => ({...e}));

  const svgEl = d3.select('#graph-svg');

  // Defs for arrows
  const defs = svgEl.append('defs');
  ['default','red','blue'].forEach(id => {
    defs.append('marker').attr('id','arr-'+id).attr('viewBox','0 -4 10 8').attr('refX',24).attr('refY',0)
      .attr('markerWidth',6).attr('markerHeight',6).attr('orient','auto')
      .append('path').attr('d','M0,-4L10,0L0,4').attr('fill', id==='red'?'#f85149':id==='blue'?'#58a6ff':'#8b949e');
  });

  const zoom = d3.zoom().scaleExtent([.2,3]).on('zoom', e => g.attr('transform', e.transform));
  svgEl.call(zoom);
  const g = svgEl.append('g');

  const sim = d3.forceSimulation(nodes)
    .force('link', d3.forceLink(links).id(d=>d.id).distance(110))
    .force('charge', d3.forceManyBody().strength(-350))
    .force('center', d3.forceCenter(W/2, H/2))
    .force('collision', d3.forceCollide(30));

  const link = g.selectAll('.edge').data(links).enter().append('line')
    .attr('stroke','#30363d').attr('stroke-width',1.5).attr('marker-end','url(#arr-default)');

  const node = g.selectAll('.node').data(nodes).enter().append('g').attr('class','node')
    .call(d3.drag().on('start',(e,d)=>{ if(!e.active) sim.alphaTarget(.3).restart(); d.fx=d.x;d.fy=d.y; })
                   .on('drag',(e,d)=>{ d.fx=e.x;d.fy=e.y; })
                   .on('end',(e,d)=>{ if(!e.active) sim.alphaTarget(0); d.fx=null;d.fy=null; }));

  node.append('circle').attr('r',18).attr('fill',d=>getColor(d.type)).attr('fill-opacity',.85)
    .attr('stroke','#0d1117').attr('stroke-width',2);
  node.append('text').attr('text-anchor','middle').attr('dy','4px').attr('font-size','9px')
    .attr('fill','#e6edf3').text(d => (d.label||d.id||'').substring(0,10));
  node.append('title').text(d => d.label || d.id);

  sim.on('tick', () => {
    link.attr('x1',d=>d.source.x).attr('y1',d=>d.source.y).attr('x2',d=>d.target.x).attr('y2',d=>d.target.y);
    node.attr('transform',d=>'translate('+d.x+','+d.y+')');
  });

  // Render path list
  const pathsEl = document.getElementById('graph-paths-list');
  if (pathsEl && data.paths) {
    pathsEl.innerHTML = data.paths.map((p,i) =>
      '<div class="path-card" onclick="highlightPath('+i+')" id="gpath'+i+'"><div class="path-title">'+esc(p.title)+'</div><div class="path-chain">'+esc((p.nodes||[]).join(' -> '))+'</div></div>'
    ).join('');
  }

  window._graphSim = sim;
  window._graphNodes = nodes;
  window._graphLinks = links;
}

function highlightPath(i) {
  document.querySelectorAll('.path-card').forEach(c => c.classList.remove('selected'));
  const card = document.getElementById('gpath' + i);
  if (card) card.classList.add('selected');
}

// ─── Compliance ───────────────────────────────────────────────────────
async function loadCompliance(target) {
  try {
    const r = await fetch('/api/compliance', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({target}) });
    const d = await r.json();
    if (!d.error) renderCompliance(d);
    else {
      const el = document.getElementById('compliance-content');
      if (el) el.innerHTML = '<div style="color:var(--muted);font-size:12px;padding:16px">Compliance map not available for this target.</div>';
    }

    // Update posture card in summary
    const pc = document.getElementById('posture-card');
    if (pc && !d.error) {
      const posture = d.overall_posture || 'UNKNOWN';
      const fws = (d.frameworks || []);
      pc.innerHTML =
        '<div><div class="posture-label">Compliance Posture</div><div class="posture-value posture-' + posture + '">' + esc(posture) + '</div></div>' +
        '<div class="posture-sep"></div>' +
        '<div><div class="posture-label">Frameworks</div><div class="frameworks-list">' +
        fws.slice(0,8).map(f => '<span class="fw-chip">'+esc(f)+'</span>').join('') +
        '</div></div>';
    }
  } catch(e) {}
}

function renderCompliance(d) {
  const el = document.getElementById('compliance-content');
  if (!el) return;
  const posture = d.overall_posture || 'UNKNOWN';
  let html = '';

  html += '<div class="compliance-section">';
  html += '<div style="font-size:22px;font-weight:700;margin-bottom:4px" class="posture-' + posture + '">' + esc(posture) + '</div>';
  html += '<div style="font-size:12px;color:var(--muted);margin-bottom:16px">Overall compliance posture</div>';
  const fws = d.frameworks || [];
  if (fws.length) html += '<div class="frameworks-list" style="margin-bottom:16px">' + fws.map(f=>'<span class="fw-chip">'+esc(f)+'</span>').join('') + '</div>';
  html += '</div>';

  const actions = d.priority_actions || [];
  if (actions.length) {
    html += '<div style="font-size:12px;font-weight:700;color:var(--red);margin-bottom:8px;text-transform:uppercase;letter-spacing:.4px">Priority Actions</div>';
    actions.slice(0,5).forEach(a => html += '<div class="priority-action">' + esc(a) + '</div>');
  }

  const mappings = d.finding_control_mappings || [];
  if (mappings.length) {
    html += '<div style="font-size:12px;font-weight:700;color:var(--muted);margin:16px 0 8px;text-transform:uppercase;letter-spacing:.4px">Finding to Control Mapping</div>';
    html += '<table class="control-table"><thead><tr><th>Finding</th><th>Severity</th><th>Framework</th><th>Control</th></tr></thead><tbody>';
    mappings.forEach(m => {
      (m.controls||[]).forEach((c,i) => {
        html += '<tr>';
        if (i===0) html += '<td rowspan="'+m.controls.length+'" style="max-width:220px">' + esc(m.finding_title) + '</td><td rowspan="'+m.controls.length+'"><span class="sev-chip sev-'+m.severity+'">'+m.severity+'</span></td>';
        html += '<td>' + esc(c.framework) + '</td><td>' + esc(c.control_id) + ' ' + esc(c.control_name||'') + '</td>';
        html += '</tr>';
      });
    });
    html += '</tbody></table>';
  }

  el.innerHTML = html;
}

// ─── Findings interactions ─────────────────────────────────────────────
function toggleF(i) { document.getElementById('fc'+i).classList.toggle('open'); }
function filterFindings(btn, sev) {
  document.querySelectorAll('.filter-chip').forEach(c=>c.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.finding-card').forEach(c => {
    c.style.display = (sev==='ALL'||c.dataset.sev===sev) ? '' : 'none';
  });
}

// ─── Export ─────────────────────────────────────────────────────────────
function copyJSON() {
  if (!currentResult) return;
  navigator.clipboard.writeText(JSON.stringify(currentResult, null, 2))
    .then(()=>alert('JSON copied to clipboard'));
}
function copyMarkdown() {
  if (!currentResult) return;
  const d = currentResult;
  let md = '# AgentScan Report: ' + (currentTarget||'') + '\n\n';
  md += '**Risk Score:** ' + (d.risk_score||0) + '/100\n\n';
  (d.attack_paths||[]).forEach(p => {
    md += '## Attack Path: ' + p.title + '\n';
    md += '**Entry:** ' + p.entry_point + '\n\n';
  });
  (d.findings||[]).filter(f=>f.severity!=='INFO').forEach(f => {
    md += '### [' + f.severity + '] ' + f.title + '\n';
    md += f.explanation + '\n\n**Fix:** ' + f.remediation + '\n\n';
  });
  navigator.clipboard.writeText(md).then(()=>alert('Markdown copied'));
}

// ─── Demo output ─────────────────────────────────────────────────────
function renderDemo(output) {
  const lines = (output||'').split('\n');
  let html = '<div class="results-wrap"><div class="result-header"><div class="result-target">Built-in Demo -- 12 Attack Scenarios</div></div><div class="demo-out">';
  lines.forEach(l => {
    const clean = l.replace(/\x1b\[[0-9;]*m/g,'');
    const col = clean.includes('[OK]')||clean.includes('PASS') ? 'var(--green)' :
                clean.includes('[X]')||clean.includes('FAIL') ? 'var(--red)' :
                clean.includes('Risk') ? 'var(--accent)' : 'var(--muted)';
    html += '<div style="color:' + col + '">' + esc(clean) + '</div>';
  });
  html += '</div></div>';
  showContent(html);
}

// ─── Init ─────────────────────────────────────────────────────────────
renderHistory();
</script>
</body>
</html>"""
