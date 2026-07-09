# -*- coding: utf-8 -*-
"""
AgentScan Dashboard
====================
One command: agentscan ui
Opens a local web interface so you can scan without memorizing CLI commands.

No server, no cloud, no accounts. Runs on localhost, shuts down when you close it.
"""
from __future__ import annotations
import threading
import time


# ---------------------------------------------------------------------------
# HTML template -- self-contained, no CDN, no external deps
# ---------------------------------------------------------------------------

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AgentScan</title>
<style>
:root {
  --bg:       #0d1117;
  --surface:  #161b22;
  --border:   #30363d;
  --text:     #e6edf3;
  --muted:    #8b949e;
  --accent:   #58a6ff;
  --red:      #f85149;
  --orange:   #d29922;
  --green:    #3fb950;
  --purple:   #bc8cff;
  --radius:   8px;
  --mono:     'Cascadia Code', 'Fira Code', Consolas, monospace;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background: var(--bg);
  color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  font-size: 14px;
  line-height: 1.6;
  height: 100vh;
  display: flex;
  flex-direction: column;
}

/* Header */
.header {
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  padding: 12px 24px;
  display: flex;
  align-items: center;
  gap: 16px;
  flex-shrink: 0;
}
.header-logo {
  font-size: 18px;
  font-weight: 700;
  color: var(--accent);
  letter-spacing: -0.5px;
}
.header-tag {
  font-size: 11px;
  color: var(--muted);
  background: var(--border);
  padding: 2px 8px;
  border-radius: 20px;
}
.header-spacer { flex: 1; }
.header-version { font-size: 11px; color: var(--muted); font-family: var(--mono); }

/* Main layout */
.main {
  display: flex;
  flex: 1;
  overflow: hidden;
}

/* Sidebar */
.sidebar {
  width: 320px;
  background: var(--surface);
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  flex-shrink: 0;
  overflow-y: auto;
}
.sidebar-section {
  padding: 16px;
  border-bottom: 1px solid var(--border);
}
.sidebar-label {
  font-size: 11px;
  font-weight: 600;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin-bottom: 10px;
}

/* Scan type tabs */
.scan-tabs {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 6px;
  margin-bottom: 12px;
}
.scan-tab {
  padding: 8px 10px;
  border-radius: var(--radius);
  border: 1px solid var(--border);
  background: transparent;
  color: var(--muted);
  font-size: 12px;
  cursor: pointer;
  text-align: center;
  transition: all 0.15s;
}
.scan-tab.active {
  border-color: var(--accent);
  color: var(--accent);
  background: rgba(88,166,255,0.08);
}
.scan-tab:hover:not(.active) { border-color: var(--muted); color: var(--text); }

/* Path input */
.path-input-wrap {
  position: relative;
  margin-bottom: 10px;
}
.path-input {
  width: 100%;
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  color: var(--text);
  font-family: var(--mono);
  font-size: 12px;
  padding: 9px 36px 9px 10px;
  outline: none;
  transition: border-color 0.15s;
}
.path-input:focus { border-color: var(--accent); }
.path-input::placeholder { color: var(--muted); }
.path-browse {
  position: absolute;
  right: 8px;
  top: 50%;
  transform: translateY(-50%);
  background: none;
  border: none;
  color: var(--muted);
  cursor: pointer;
  font-size: 16px;
  padding: 2px;
}
.path-browse:hover { color: var(--accent); }

/* Options */
.option-row {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 6px;
  font-size: 12px;
  color: var(--muted);
  cursor: pointer;
}
.option-row input[type=checkbox] { accent-color: var(--accent); cursor: pointer; }
.option-row:hover { color: var(--text); }

select.option-select {
  background: var(--bg);
  border: 1px solid var(--border);
  color: var(--text);
  border-radius: 4px;
  padding: 4px 6px;
  font-size: 12px;
  outline: none;
  cursor: pointer;
}

/* Scan button */
.scan-btn {
  width: 100%;
  padding: 11px;
  background: var(--accent);
  color: #0d1117;
  border: none;
  border-radius: var(--radius);
  font-size: 14px;
  font-weight: 700;
  cursor: pointer;
  transition: opacity 0.15s, transform 0.1s;
}
.scan-btn:hover { opacity: 0.9; }
.scan-btn:active { transform: scale(0.98); }
.scan-btn:disabled { opacity: 0.4; cursor: not-allowed; }

/* History */
.history-item {
  padding: 8px 10px;
  border-radius: 6px;
  cursor: pointer;
  font-size: 12px;
  color: var(--muted);
  display: flex;
  align-items: center;
  gap: 8px;
  transition: background 0.1s;
}
.history-item:hover { background: var(--bg); color: var(--text); }
.history-item .risk-dot {
  width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0;
}
.history-item .hist-path { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.history-item .hist-time { font-size: 10px; color: var(--muted); flex-shrink: 0; }
.empty-history { font-size: 12px; color: var(--muted); text-align: center; padding: 20px 0; }

/* Content area */
.content {
  flex: 1;
  overflow-y: auto;
  padding: 24px;
}

/* Welcome state */
.welcome {
  max-width: 600px;
  margin: 40px auto;
  text-align: center;
}
.welcome-icon { font-size: 48px; margin-bottom: 16px; }
.welcome h2 { font-size: 22px; font-weight: 600; margin-bottom: 8px; color: var(--text); }
.welcome p { color: var(--muted); margin-bottom: 24px; line-height: 1.7; }
.welcome-steps {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 12px;
  text-align: left;
}
.welcome-step {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 14px;
}
.step-num { font-size: 10px; color: var(--accent); font-weight: 700; margin-bottom: 6px; }
.step-title { font-size: 13px; font-weight: 600; margin-bottom: 4px; }
.step-desc { font-size: 11px; color: var(--muted); }

/* Loading state */
.loading {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  min-height: 300px;
  gap: 16px;
}
.spinner {
  width: 40px; height: 40px;
  border: 3px solid var(--border);
  border-top-color: var(--accent);
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }
.loading-text { color: var(--muted); font-size: 14px; }

/* Results */
.result-header {
  display: flex;
  align-items: center;
  gap: 16px;
  margin-bottom: 24px;
  flex-wrap: wrap;
}
.result-target {
  font-family: var(--mono);
  font-size: 13px;
  color: var(--muted);
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.result-actions { display: flex; gap: 8px; }
.btn-sm {
  padding: 5px 12px;
  border-radius: 6px;
  border: 1px solid var(--border);
  background: transparent;
  color: var(--muted);
  font-size: 12px;
  cursor: pointer;
  transition: all 0.15s;
}
.btn-sm:hover { border-color: var(--accent); color: var(--accent); }

/* Metric cards */
.metrics {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 12px;
  margin-bottom: 24px;
}
.metric {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 16px;
}
.metric-label { font-size: 11px; color: var(--muted); margin-bottom: 6px; }
.metric-value { font-size: 28px; font-weight: 700; line-height: 1; }
.metric-sub { font-size: 11px; color: var(--muted); margin-top: 4px; }
.risk-bar { height: 4px; background: var(--border); border-radius: 2px; margin-top: 8px; }
.risk-fill { height: 100%; border-radius: 2px; transition: width 0.6s ease; }

/* Attack paths */
.section-title {
  font-size: 13px;
  font-weight: 600;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin-bottom: 12px;
  margin-top: 24px;
  display: flex;
  align-items: center;
  gap: 8px;
}
.section-title::after {
  content: '';
  flex: 1;
  height: 1px;
  background: var(--border);
}

.path-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-left: 3px solid var(--red);
  border-radius: var(--radius);
  padding: 14px 16px;
  margin-bottom: 10px;
  cursor: pointer;
  transition: border-color 0.15s;
}
.path-card:hover { border-color: var(--red); background: rgba(248,81,73,0.04); }
.path-title { font-size: 13px; font-weight: 600; margin-bottom: 6px; }
.path-chain {
  font-family: var(--mono);
  font-size: 11px;
  color: var(--accent);
  margin-bottom: 6px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.path-meta { font-size: 11px; color: var(--muted); display: flex; gap: 16px; }

/* Findings */
.findings-filter {
  display: flex;
  gap: 6px;
  margin-bottom: 14px;
  flex-wrap: wrap;
}
.filter-chip {
  padding: 4px 12px;
  border-radius: 20px;
  border: 1px solid var(--border);
  background: transparent;
  color: var(--muted);
  font-size: 11px;
  cursor: pointer;
  transition: all 0.15s;
}
.filter-chip.active { border-color: var(--accent); color: var(--accent); background: rgba(88,166,255,0.1); }
.filter-chip:hover:not(.active) { border-color: var(--muted); }

.finding-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  margin-bottom: 8px;
  overflow: hidden;
}
.finding-header {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 14px;
  cursor: pointer;
}
.finding-header:hover { background: rgba(255,255,255,0.02); }
.sev-chip {
  font-size: 10px;
  font-weight: 700;
  padding: 2px 8px;
  border-radius: 4px;
  letter-spacing: 0.3px;
  flex-shrink: 0;
}
.sev-CRITICAL { background: rgba(248,81,73,0.15); color: var(--red); }
.sev-HIGH { background: rgba(210,153,34,0.15); color: var(--orange); }
.sev-MEDIUM { background: rgba(210,153,34,0.08); color: var(--orange); }
.sev-LOW { background: rgba(88,166,255,0.1); color: var(--accent); }
.sev-INFO { background: var(--border); color: var(--muted); }
.finding-title { flex: 1; font-size: 13px; font-weight: 500; min-width: 0; }
.finding-chevron { color: var(--muted); font-size: 12px; flex-shrink: 0; transition: transform 0.2s; }
.finding-card.open .finding-chevron { transform: rotate(90deg); }

.finding-body {
  display: none;
  padding: 0 14px 14px;
  border-top: 1px solid var(--border);
}
.finding-card.open .finding-body { display: block; }
.finding-section { margin-top: 10px; }
.finding-section-label { font-size: 10px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; }
.finding-section-text { font-size: 12px; color: var(--text); line-height: 1.6; }
.finding-fix {
  background: rgba(63,185,80,0.06);
  border: 1px solid rgba(63,185,80,0.2);
  border-radius: 6px;
  padding: 8px 10px;
  font-size: 12px;
  color: #3fb950;
  margin-top: 10px;
}
.finding-evidence {
  background: var(--bg);
  border-radius: 6px;
  padding: 8px 10px;
  font-family: var(--mono);
  font-size: 11px;
  color: var(--muted);
  margin-top: 8px;
}
.mitre-tags { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 8px; }
.mitre-tag {
  background: rgba(188,140,255,0.1);
  color: var(--purple);
  border-radius: 4px;
  padding: 2px 6px;
  font-size: 10px;
  font-family: var(--mono);
}

/* Error state */
.error-box {
  background: rgba(248,81,73,0.08);
  border: 1px solid rgba(248,81,73,0.3);
  border-radius: var(--radius);
  padding: 16px;
  color: var(--red);
  font-size: 13px;
  line-height: 1.7;
  margin: 40px auto;
  max-width: 600px;
}
.error-box pre {
  margin-top: 8px;
  font-family: var(--mono);
  font-size: 11px;
  color: var(--muted);
  white-space: pre-wrap;
  word-break: break-all;
}

/* Scrollbar */
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--muted); }
</style>
</head>
<body>

<div class="header">
  <div class="header-logo">AgentScan</div>
  <div class="header-tag">AI Agent Security Scanner</div>
  <div class="header-spacer"></div>
  <div class="header-version" id="ver">v__VERSION__</div>
</div>

<div class="main">
  <!-- Sidebar -->
  <div class="sidebar">
    <div class="sidebar-section">
      <div class="sidebar-label">Scan type</div>
      <div class="scan-tabs">
        <button class="scan-tab active" data-type="source" onclick="setType(this,'source')">Source Code</button>
        <button class="scan-tab" data-type="agent" onclick="setType(this,'agent')">Config File</button>
        <button class="scan-tab" data-type="mcp" onclick="setType(this,'mcp')">MCP Server</button>
        <button class="scan-tab" data-type="demo" onclick="setType(this,'demo')">Demo</button>
      </div>

      <div id="path-area">
        <div class="sidebar-label" id="path-label">Path to scan</div>
        <div class="path-input-wrap">
          <input class="path-input" id="path-input" type="text"
                 placeholder="./src/agents/ or ./agent.yaml"
                 onkeydown="if(event.key==='Enter') runScan()">
          <button class="path-browse" title="Paste from clipboard" onclick="pasteFromClipboard()">&#128203;</button>
        </div>
        <div style="font-size:11px;color:var(--muted);margin-bottom:12px" id="path-hint">
          Tip: copy the folder path in Explorer, click the clipboard icon, then scan
        </div>
      </div>

      <div id="options-area">
        <div class="sidebar-label">Options</div>
        <label class="option-row">
          <input type="checkbox" id="opt-fail-on"> Stop CI on CRITICAL
        </label>
        <label class="option-row" style="margin-bottom:10px;">
          <span style="color:var(--muted);font-size:12px;margin-right:4px;">Output:</span>
          <select class="option-select" id="opt-output">
            <option value="json">JSON (default)</option>
            <option value="html">HTML report</option>
            <option value="sarif">SARIF (GitHub)</option>
          </select>
        </label>
      </div>

      <button class="scan-btn" id="scan-btn" onclick="runScan()">Scan</button>
    </div>

    <div class="sidebar-section" style="flex:1">
      <div class="sidebar-label">Recent scans</div>
      <div id="history-list"><div class="empty-history">No scans yet</div></div>
    </div>
  </div>

  <!-- Content -->
  <div class="content" id="content">
    <div class="welcome">
      <div class="welcome-icon">&#128737;</div>
      <h2>Find attack paths before attackers do</h2>
      <p>AgentScan scans your AI agent code and configs for dangerous tool<br>
         combinations that create real attack chains -- not just permission lists.</p>
      <div class="welcome-steps">
        <div class="welcome-step">
          <div class="step-num">01</div>
          <div class="step-title">Choose scan type</div>
          <div class="step-desc">Source code, config file, MCP server, or try the built-in demo</div>
        </div>
        <div class="welcome-step">
          <div class="step-num">02</div>
          <div class="step-title">Enter your path</div>
          <div class="step-desc">Paste a folder path from Explorer or type a file path directly</div>
        </div>
        <div class="welcome-step">
          <div class="step-num">03</div>
          <div class="step-title">See attack chains</div>
          <div class="step-desc">Risk score, complete attack paths, findings with fixes and MITRE mapping</div>
        </div>
      </div>
    </div>
  </div>
</div>

<script>
let currentType = 'source';
let scanHistory = [];

function setType(btn, type) {
  document.querySelectorAll('.scan-tab').forEach(t => t.classList.remove('active'));
  btn.classList.add('active');
  currentType = type;
  const pathArea = document.getElementById('path-area');
  const optArea = document.getElementById('options-area');
  const hint = document.getElementById('path-hint');
  const inp = document.getElementById('path-input');
  const lbl = document.getElementById('path-label');
  if (type === 'demo') {
    pathArea.style.display = 'none';
    optArea.style.display = 'none';
    document.getElementById('scan-btn').textContent = 'Run Demo (12 scenarios)';
  } else {
    pathArea.style.display = '';
    optArea.style.display = '';
    document.getElementById('scan-btn').textContent = 'Scan';
    if (type === 'source') {
      lbl.textContent = 'Path to Python source';
      inp.placeholder = './src/agents/  or  ./agent.py';
      hint.textContent = 'Tip: copy the folder path from Explorer, click the clipboard icon';
    } else if (type === 'agent') {
      lbl.textContent = 'Config file path';
      inp.placeholder = './agent.yaml  or  ./agent.json';
      hint.textContent = 'Supports YAML and JSON agent configs, Dify, n8n, Flowise exports';
    } else if (type === 'mcp') {
      lbl.textContent = 'MCP manifest or URL';
      inp.placeholder = './mcp_server.json  or  https://...';
      hint.textContent = 'Pass a local manifest file or a live MCP server URL';
    }
  }
}

async function pasteFromClipboard() {
  try {
    const text = await navigator.clipboard.readText();
    document.getElementById('path-input').value = text.trim();
  } catch(e) {
    alert('Could not read clipboard. Paste manually with Ctrl+V.');
  }
}

function riskColor(score) {
  if (score >= 70) return 'var(--red)';
  if (score >= 40) return 'var(--orange)';
  if (score >= 10) return '#e3b341';
  return 'var(--green)';
}
function riskLabel(score) {
  if (score >= 70) return 'CRITICAL';
  if (score >= 40) return 'HIGH';
  if (score >= 10) return 'MEDIUM';
  return 'LOW';
}

function showLoading(msg) {
  document.getElementById('content').innerHTML =
    '<div class="loading"><div class="spinner"></div><div class="loading-text">' + msg + '</div></div>';
}

async function runScan() {
  const btn = document.getElementById('scan-btn');
  btn.disabled = true;
  btn.textContent = 'Scanning...';

  const target = currentType === 'demo' ? '' : document.getElementById('path-input').value.trim();

  if (currentType !== 'demo' && !target) {
    alert('Please enter a path to scan');
    btn.disabled = false;
    btn.textContent = 'Scan';
    return;
  }

  const loadingMessages = {
    source: 'Scanning Python source files...',
    agent: 'Scanning agent config...',
    mcp: 'Scanning MCP server...',
    demo: 'Running 12 attack scenarios...',
  };
  showLoading(loadingMessages[currentType] || 'Scanning...');

  try {
    const resp = await fetch('/api/scan', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ type: currentType, target: target })
    });
    const data = await resp.json();
    renderResult(data, target || 'demo');
  } catch(e) {
    document.getElementById('content').innerHTML =
      '<div class="error-box"><strong>Could not reach scan API</strong><pre>' + e.message + '</pre></div>';
  } finally {
    btn.disabled = false;
    btn.textContent = currentType === 'demo' ? 'Run Demo (12 scenarios)' : 'Scan';
  }
}

function renderResult(data, target) {
  if (data.error) {
    document.getElementById('content').innerHTML =
      '<div class="error-box"><strong>Scan error</strong><pre>' + escHtml(data.error) + '</pre></div>';
    return;
  }

  if (data.demo_output) {
    renderDemoResult(data);
    return;
  }

  const score = data.risk_score || 0;
  const findings = data.findings || [];
  const paths = data.attack_paths || [];
  const reportable = findings.filter(f => f.severity !== 'INFO');
  const counts = {CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0, INFO:0};
  findings.forEach(f => { if (counts[f.severity] !== undefined) counts[f.severity]++; });

  // Add to history
  addHistory(target, score, data.scanner_type);

  let html = '';

  // Header
  html += '<div class="result-header">';
  html += '<div class="result-target">' + escHtml(target) + '</div>';
  html += '<div class="result-actions">';
  html += '<button class="btn-sm" onclick="copyJson(' + escJson(JSON.stringify(data)) + ')">Copy JSON</button>';
  html += '</div></div>';

  // Metrics
  html += '<div class="metrics">';
  html += '<div class="metric"><div class="metric-label">Risk Score</div>';
  html += '<div class="metric-value" style="color:' + riskColor(score) + '">' + score + '<span style="font-size:16px;color:var(--muted)">/100</span></div>';
  html += '<div class="metric-sub">' + riskLabel(score) + '</div>';
  html += '<div class="risk-bar"><div class="risk-fill" style="width:' + score + '%;background:' + riskColor(score) + '"></div></div></div>';

  html += '<div class="metric"><div class="metric-label">Critical</div>';
  html += '<div class="metric-value" style="color:var(--red)">' + counts.CRITICAL + '</div>';
  html += '<div class="metric-sub">' + counts.HIGH + ' high</div></div>';

  html += '<div class="metric"><div class="metric-label">Attack Paths</div>';
  html += '<div class="metric-value" style="color:' + (paths.length > 0 ? 'var(--red)' : 'var(--green)') + '">' + paths.length + '</div>';
  html += '<div class="metric-sub">complete chains</div></div>';

  html += '<div class="metric"><div class="metric-label">Findings</div>';
  html += '<div class="metric-value">' + reportable.length + '</div>';
  html += '<div class="metric-sub">' + counts.MEDIUM + ' med  ' + counts.LOW + ' low</div></div>';
  html += '</div>';

  // Attack paths
  if (paths.length > 0) {
    html += '<div class="section-title">Attack Paths</div>';
    paths.forEach(p => {
      const steps = (p.steps || []).map(s => s.title ? s.title.split("'")[1] || s.title : '').filter(Boolean);
      html += '<div class="path-card">';
      html += '<div class="path-title">' + escHtml(p.title) + '</div>';
      if (steps.length) html += '<div class="path-chain">Prompt -> ' + steps.slice(0,4).map(escHtml).join(' -> ') + '</div>';
      html += '<div class="path-meta">';
      html += '<span>Entry: ' + escHtml(p.entry_point || '') + '</span>';
      if ((p.mitre_atlas||[]).length) html += '<span>' + p.mitre_atlas.join(', ') + '</span>';
      html += '</div></div>';
    });
  }

  // Findings
  if (reportable.length > 0) {
    html += '<div class="section-title">Findings</div>';
    html += '<div class="findings-filter">';
    html += '<button class="filter-chip active" onclick="filterFindings(this,\'ALL\')">All (' + reportable.length + ')</button>';
    ['CRITICAL','HIGH','MEDIUM','LOW'].forEach(s => {
      if (counts[s] > 0)
        html += '<button class="filter-chip" onclick="filterFindings(this,\'' + s + '\')">' + s + ' (' + counts[s] + ')</button>';
    });
    html += '</div>';
    html += '<div id="findings-list">';
    reportable.forEach((f, i) => {
      html += '<div class="finding-card" data-sev="' + f.severity + '" id="fc' + i + '">';
      html += '<div class="finding-header" onclick="toggleFinding(' + i + ')">';
      html += '<span class="sev-chip sev-' + f.severity + '">' + f.severity + '</span>';
      html += '<span class="finding-title">' + escHtml(f.title) + '</span>';
      html += '<span class="finding-chevron">&#9654;</span>';
      html += '</div>';
      html += '<div class="finding-body">';
      if (f.explanation) {
        html += '<div class="finding-section"><div class="finding-section-label">What</div>';
        html += '<div class="finding-section-text">' + escHtml(f.explanation) + '</div></div>';
      }
      if (f.impact) {
        html += '<div class="finding-section"><div class="finding-section-label">Impact</div>';
        html += '<div class="finding-section-text">' + escHtml(f.impact) + '</div></div>';
      }
      if (f.remediation) {
        html += '<div class="finding-fix"><strong>Fix:</strong> ' + escHtml(f.remediation) + '</div>';
      }
      if (f.evidence && f.evidence.length) {
        html += '<div class="finding-evidence">' + f.evidence.map(e => escHtml(e.source + ': ' + e.observed_value)).join('<br>') + '</div>';
      }
      if (f.mitre_atlas && f.mitre_atlas.length) {
        html += '<div class="mitre-tags">' + f.mitre_atlas.map(m => '<span class="mitre-tag">' + m + '</span>').join('') + '</div>';
      }
      html += '</div></div>';
    });
    html += '</div>';
  } else {
    html += '<div style="text-align:center;color:var(--green);padding:40px;font-size:14px">No reportable findings -- this looks well-scoped.</div>';
  }

  document.getElementById('content').innerHTML = html;
}

function renderDemoResult(data) {
  let html = '<div class="result-header"><div class="result-target">Demo -- 12 built-in attack scenarios</div></div>';
  const lines = (data.demo_output || '').split('\n');
  html += '<div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;font-family:var(--mono);font-size:12px;line-height:1.8;">';
  lines.forEach(l => {
    const clean = l.replace(/\x1b\[[0-9;]*m/g, '');
    if (clean.includes('[OK]') || clean.includes('PASS')) {
      html += '<div style="color:var(--green)">' + escHtml(clean) + '</div>';
    } else if (clean.includes('[X]') || clean.includes('FAIL')) {
      html += '<div style="color:var(--red)">' + escHtml(clean) + '</div>';
    } else if (clean.includes('Risk')) {
      html += '<div style="color:var(--accent)">' + escHtml(clean) + '</div>';
    } else {
      html += '<div style="color:var(--muted)">' + escHtml(clean) + '</div>';
    }
  });
  html += '</div>';
  document.getElementById('content').innerHTML = html;
}

function toggleFinding(i) {
  const card = document.getElementById('fc' + i);
  card.classList.toggle('open');
}

function filterFindings(btn, sev) {
  document.querySelectorAll('.filter-chip').forEach(c => c.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.finding-card').forEach(c => {
    c.style.display = (sev === 'ALL' || c.dataset.sev === sev) ? '' : 'none';
  });
}

function addHistory(target, score, type) {
  const item = { target, score, type, time: new Date().toLocaleTimeString() };
  scanHistory.unshift(item);
  if (scanHistory.length > 10) scanHistory.pop();
  renderHistory();
}

function renderHistory() {
  const list = document.getElementById('history-list');
  if (!scanHistory.length) { list.innerHTML = '<div class="empty-history">No scans yet</div>'; return; }
  list.innerHTML = scanHistory.map((h, i) => {
    const col = riskColor(h.score);
    return '<div class="history-item" onclick="loadHistory(' + i + ')">' +
      '<div class="risk-dot" style="background:' + col + '"></div>' +
      '<div class="hist-path">' + escHtml(h.target) + '</div>' +
      '<div class="hist-time">' + h.time + '</div>' +
      '</div>';
  }).join('');
}

function loadHistory(i) {
  const h = scanHistory[i];
  if (!h) return;
  currentType = h.type || 'source';
  document.getElementById('path-input').value = h.target;
  const tab = document.querySelector('[data-type="' + currentType + '"]');
  if (tab) { document.querySelectorAll('.scan-tab').forEach(t=>t.classList.remove('active')); tab.classList.add('active'); }
  runScan();
}

function escHtml(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function escJson(s) { return JSON.stringify(s); }

function copyJson(data) {
  navigator.clipboard.writeText(typeof data === 'string' ? data : JSON.stringify(data, null, 2))
    .then(() => alert('JSON copied to clipboard'));
}
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

def create_app(version: str = "0.2.6"):
    from flask import Flask, request, jsonify, Response
    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False

    html = HTML.replace("__VERSION__", version)

    @app.route("/")
    def index():
        return Response(html, mimetype="text/html")

    @app.route("/api/scan", methods=["POST"])
    def api_scan():
        data = request.get_json(force=True)
        scan_type = data.get("type", "source")
        target = data.get("target", "").strip()

        if scan_type == "demo":
            return _run_demo()

        if not target:
            return jsonify({"error": "No path provided"}), 400

        try:
            if scan_type == "source":
                from agentscan.scanners.source_scanner import scan_source
                result = scan_source(target)
            elif scan_type == "agent":
                from agentscan.scanners.agent_scanner import scan_agent_config
                result = scan_agent_config(target)
            elif scan_type == "mcp":
                from agentscan.scanners.mcp_scanner import scan_mcp
                result = scan_mcp(target)
            else:
                return jsonify({"error": "Unknown scan type: " + scan_type}), 400
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

        return jsonify(_result_to_dict(result))

    def _run_demo():
        import subprocess
        try:
            r = subprocess.run(
                ["agentscan", "demo"],
                capture_output=True, text=True, encoding="utf-8", timeout=120
            )
            return jsonify({"demo_output": r.stdout + r.stderr})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    def _result_to_dict(result) -> dict:
        """Convert ScanResult to a JSON-serialisable dict."""
        def finding_dict(f):
            return {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "confidence": f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence),
                "explanation": f.explanation,
                "impact": f.impact,
                "remediation": f.remediation,
                "mitre_atlas": list(f.mitre_atlas or []),
                "evidence": [
                    {"source": e.source, "observed_value": str(e.observed_value)}
                    for e in (f.evidence or [])
                ],
                "tags": list(f.tags or []),
            }

        def path_dict(p):
            return {
                "id": p.id,
                "title": p.title,
                "severity": p.severity.value if hasattr(p.severity, "value") else str(p.severity),
                "entry_point": p.entry_point,
                "impact": p.impact,
                "mitre_atlas": list(p.mitre_atlas or []),
                "steps": [
                    {"id": s.id, "title": s.title,
                     "severity": s.severity.value if hasattr(s.severity, "value") else str(s.severity)}
                    for s in (p.steps or [])
                ],
            }

        counts = {}
        for f in (result.findings or []):
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            counts[sev] = counts.get(sev, 0) + 1

        return {
            "target": result.target,
            "scanner_type": result.scanner_type,
            "risk_score": result.risk_score() if callable(getattr(result, "risk_score", None)) else 0,
            "error": result.error,
            "findings": [finding_dict(f) for f in (result.findings or [])],
            "attack_paths": [path_dict(p) for p in (result.attack_paths or [])],
            "summary": counts,
            "metadata": result.metadata or {},
        }

    return app


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def run_ui(port: int = 0, open_browser: bool = True):
    """Start the AgentScan dashboard."""
    import socket

    if port == 0:
        with socket.socket() as s:
            s.bind(("", 0))
            port = s.getsockname()[1]

    from agentscan import __version__
    app = create_app(__version__)

    url = "http://localhost:" + str(port)
    print("")
    print("  AgentScan Dashboard")
    print("  " + url)
    print("  Press Ctrl+C to stop")
    print("")

    if open_browser:
        def _open():
            time.sleep(0.8)
            import subprocess
            import sys
            try:
                if sys.platform == "win32":
                    subprocess.Popen(["cmd", "/c", "start", "", url], shell=False,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                elif sys.platform == "darwin":
                    subprocess.Popen(["open", url],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                else:
                    subprocess.Popen(["xdg-open", url],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
        threading.Thread(target=_open, daemon=True).start()

    import logging
    log = logging.getLogger("werkzeug")
    log.setLevel(logging.ERROR)
    app.run(host="localhost", port=port, debug=False, use_reloader=False)
