# -*- coding: utf-8 -*-
"""Dashboard HTML -- complete rewrite with all tabs"""
from __future__ import annotations
from pathlib import Path

_ASSETS = Path(__file__).parent / "outputs" / "assets"

def _js(name):
    p = _ASSETS / name
    return p.read_text(encoding="utf-8") if p.exists() else ""

def get_dashboard_html(version=""):
    d3 = _js("d3.min.js")
    return _TEMPLATE.replace("__D3__", d3).replace("__VERSION__", version)

_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AgentScan</title>
<style>
:root{--bg:#0d1117;--surface:#161b22;--s2:#1c2230;--border:#30363d;--text:#e6edf3;--muted:#8b949e;--accent:#58a6ff;--red:#f85149;--orange:#e3b341;--green:#3fb950;--purple:#bc8cff;--radius:8px;--mono:'Cascadia Code','Fira Code',Consolas,monospace}
*{box-sizing:border-box;margin:0;padding:0}html,body{height:100%}
body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:14px;line-height:1.5;display:flex;flex-direction:column;overflow:hidden}
.topbar{display:flex;align-items:center;gap:12px;padding:0 20px;height:48px;background:var(--surface);border-bottom:1px solid var(--border);flex-shrink:0}
.logo{font-size:16px;font-weight:700;color:var(--accent)}.logo-sub{font-size:11px;color:var(--muted)}.ts{flex:1}
.vbadge{font-size:11px;font-family:var(--mono);color:var(--muted);background:var(--border);padding:2px 8px;border-radius:20px}
.layout{display:flex;flex:1;overflow:hidden}
.sidebar{width:290px;flex-shrink:0;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;overflow-y:auto}
.sb-block{padding:14px;border-bottom:1px solid var(--border)}
.sb-label{font-size:10px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin-bottom:8px}
.mode-tabs{display:grid;grid-template-columns:1fr 1fr;gap:4px;margin-bottom:10px}
.mode-tab{padding:6px 4px;border-radius:6px;border:1px solid var(--border);background:transparent;color:var(--muted);font-size:11px;cursor:pointer;text-align:center;transition:all .15s}
.mode-tab.active{border-color:var(--accent);color:var(--accent);background:rgba(88,166,255,.08)}
.mode-tab:hover:not(.active){border-color:var(--muted);color:var(--text)}
.inp-row{display:flex;gap:5px;margin-bottom:6px}
.txt-in{flex:1;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:var(--mono);font-size:11px;padding:7px 9px;outline:none;transition:border-color .15s}
.txt-in:focus{border-color:var(--accent)}.txt-in::placeholder{color:var(--muted)}
.icon-btn{background:var(--border);border:none;color:var(--muted);border-radius:6px;width:30px;height:30px;cursor:pointer;font-size:13px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.icon-btn:hover{background:var(--accent);color:#0d1117}
.hint{font-size:10px;color:var(--muted);line-height:1.6;margin-bottom:8px}
.drop-zone{border:2px dashed var(--border);border-radius:var(--radius);padding:18px 12px;text-align:center;cursor:pointer;transition:all .15s;margin-bottom:8px}
.drop-zone:hover,.drop-zone.over{border-color:var(--accent);background:rgba(88,166,255,.05)}
.dz-icon{font-size:24px;margin-bottom:5px}.dz-t{font-size:12px;font-weight:600;margin-bottom:3px}.dz-h{font-size:10px;color:var(--muted)}
.det-badge{display:none;align-items:center;gap:5px;font-size:10px;color:var(--green);margin-bottom:6px}
.det-badge.show{display:flex}.det-badge::before{content:'';width:6px;height:6px;border-radius:50%;background:var(--green)}
.pkg-tabs{display:flex;gap:4px;margin-bottom:7px}
.pkg-tab{font-size:10px;padding:3px 8px;border-radius:20px;border:1px solid var(--border);background:transparent;color:var(--muted);cursor:pointer}
.pkg-tab.active{border-color:var(--accent);color:var(--accent);background:rgba(88,166,255,.1)}
.scan-btn{width:100%;padding:10px;font-size:14px;font-weight:700;background:var(--accent);color:#0d1117;border:none;border-radius:var(--radius);cursor:pointer;transition:opacity .15s;margin-bottom:6px}
.scan-btn:hover{opacity:.88}.scan-btn:disabled{opacity:.4;cursor:not-allowed}
.demo-btn{width:100%;padding:6px;font-size:11px;background:transparent;border:1px solid var(--border);color:var(--muted);border-radius:6px;cursor:pointer}
.demo-btn:hover{border-color:var(--accent);color:var(--accent)}
.hist-item{display:flex;align-items:center;gap:7px;padding:5px 7px;border-radius:6px;cursor:pointer;transition:background .1s}
.hist-item:hover{background:var(--bg)}
.hdot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
.hpath{flex:1;font-size:11px;font-family:var(--mono);color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.htime{font-size:10px;color:var(--muted);flex-shrink:0}
.hdiff{font-size:10px;flex-shrink:0}
.content{flex:1;overflow-y:auto}
.welcome{max-width:600px;margin:50px auto;padding:0 24px;text-align:center}
.welcome-icon{font-size:48px;margin-bottom:14px}.welcome h2{font-size:20px;font-weight:700;margin-bottom:8px}
.welcome p{color:var(--muted);margin-bottom:24px;line-height:1.7}
.wcards{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;text-align:left}
.wcard{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:12px}
.wcard-n{font-size:10px;color:var(--accent);font-weight:700;margin-bottom:5px}
.wcard-t{font-size:12px;font-weight:600;margin-bottom:3px}.wcard-d{font-size:11px;color:var(--muted);line-height:1.5}
.rw{padding:18px 22px}
.rhead{display:flex;align-items:center;gap:10px;margin-bottom:16px;flex-wrap:wrap}
.rtarget{font-family:var(--mono);font-size:11px;color:var(--muted);flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.rtype{font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;background:rgba(88,166,255,.1);color:var(--accent);text-transform:uppercase;flex-shrink:0}
.act-btns{display:flex;gap:5px;flex-shrink:0}
.btn-sm{padding:4px 10px;border-radius:6px;border:1px solid var(--border);background:transparent;color:var(--muted);font-size:11px;cursor:pointer;transition:all .15s}
.btn-sm:hover{border-color:var(--accent);color:var(--accent)}
.tabs{display:flex;gap:2px;border-bottom:1px solid var(--border);margin-bottom:18px;overflow-x:auto}
.tab{padding:7px 13px;font-size:12px;color:var(--muted);cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-1px;white-space:nowrap;transition:all .15s}
.tab.active{color:var(--accent);border-bottom-color:var(--accent)}
.tab:hover:not(.active){color:var(--text)}
.tbadge{font-size:9px;font-weight:700;padding:1px 5px;border-radius:20px;background:var(--border);color:var(--muted);margin-left:4px}
.tab.active .tbadge{background:rgba(88,166,255,.15);color:var(--accent)}
.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:16px}
.metric{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:14px}
.mlbl{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.4px;margin-bottom:5px}
.mval{font-size:28px;font-weight:700;line-height:1}.msub{font-size:10px;color:var(--muted);margin-top:3px}
.rbar{height:4px;background:var(--border);border-radius:2px;margin-top:8px;overflow:hidden}
.rfill{height:100%;border-radius:2px;transition:width .8s ease}
.sev-strip{display:flex;gap:7px;flex-wrap:wrap;margin-bottom:16px}
.sev-pill{display:flex;align-items:center;gap:6px;padding:5px 11px;border-radius:6px;font-size:11px;font-weight:600;border:1px solid}
.sp-CRITICAL{background:rgba(248,81,73,.1);color:var(--red);border-color:rgba(248,81,73,.3)}
.sp-HIGH{background:rgba(227,179,65,.1);color:var(--orange);border-color:rgba(227,179,65,.3)}
.sp-MEDIUM{background:rgba(227,179,65,.06);color:var(--orange);border-color:rgba(227,179,65,.2)}
.sp-LOW{background:rgba(88,166,255,.08);color:var(--accent);border-color:rgba(88,166,255,.2)}
.sp-INFO{background:var(--border);color:var(--muted);border-color:var(--border)}
.sev-n{font-size:15px}
.posture-card{border:1px solid var(--border);border-radius:var(--radius);padding:14px 18px;margin-bottom:16px;display:flex;align-items:center;gap:14px}
.plbl{font-size:10px;color:var(--muted);margin-bottom:3px}.pval{font-size:18px;font-weight:700}
.p-non-compliant{color:var(--red)}.p-compliant{color:var(--green)}.p-unknown{color:var(--muted)}
.psep{width:1px;background:var(--border);align-self:stretch}
.fw-chips{display:flex;gap:5px;flex-wrap:wrap}
.fw-chip{font-size:10px;padding:2px 7px;border-radius:4px;background:rgba(188,140,255,.1);color:var(--purple);border:1px solid rgba(188,140,255,.2)}
.pcard{background:var(--surface);border:1px solid var(--border);border-left:3px solid var(--red);border-radius:var(--radius);padding:11px 13px;cursor:pointer;transition:background .15s;margin-bottom:8px}
.pcard:hover{background:var(--s2)}.pcard.sel{border-left-color:var(--accent)}
.ptitle{font-size:12px;font-weight:600;margin-bottom:4px}
.pchain{font-family:var(--mono);font-size:10px;color:var(--accent);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.pentry{font-size:10px;color:var(--muted);margin-top:3px}
.graph-wrap{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);height:420px;position:relative;overflow:hidden;margin-bottom:14px}
#gsvg{width:100%;height:100%}
.glegend{display:flex;gap:14px;flex-wrap:wrap;font-size:11px;color:var(--muted);margin-bottom:14px}
.gli{display:flex;align-items:center;gap:4px}
.gldot{width:9px;height:9px;border-radius:50%}
.path-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.fbar{display:flex;gap:5px;flex-wrap:wrap;margin-bottom:12px;align-items:center}
.fchip{padding:3px 11px;border-radius:20px;border:1px solid var(--border);background:transparent;color:var(--muted);font-size:11px;cursor:pointer}
.fchip.active{border-color:var(--accent);color:var(--accent);background:rgba(88,166,255,.1)}
.fchip:hover:not(.active){border-color:var(--muted)}
.fcard{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:7px;overflow:hidden}
.fhead{display:flex;align-items:center;gap:9px;padding:10px 13px;cursor:pointer}
.fhead:hover{background:rgba(255,255,255,.02)}
.schip{font-size:10px;font-weight:700;padding:2px 6px;border-radius:4px;letter-spacing:.3px;flex-shrink:0}
.sc-CRITICAL{background:rgba(248,81,73,.12);color:var(--red)}
.sc-HIGH{background:rgba(227,179,65,.12);color:var(--orange)}
.sc-MEDIUM{background:rgba(227,179,65,.07);color:var(--orange)}
.sc-LOW{background:rgba(88,166,255,.09);color:var(--accent)}
.sc-INFO{background:var(--border);color:var(--muted)}
.ftitle{flex:1;font-size:12px;min-width:0}
.chev{color:var(--muted);font-size:10px;flex-shrink:0;transition:transform .2s}
.fcard.open .chev{transform:rotate(90deg)}
.fbody{display:none;padding:0 13px 13px}
.fcard.open .fbody{display:block}
.fslbl{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.4px;margin-bottom:2px;margin-top:9px}
.fstxt{font-size:12px;line-height:1.6}
.ffix{background:rgba(63,185,80,.06);border:1px solid rgba(63,185,80,.2);border-radius:6px;padding:8px 10px;font-size:12px;color:var(--green);margin-top:9px}
.fevid{background:var(--bg);border-radius:6px;padding:7px 9px;font-family:var(--mono);font-size:10px;color:var(--muted);margin-top:7px;line-height:1.7}
.mtags{display:flex;gap:4px;flex-wrap:wrap;margin-top:7px}
.mtag{background:rgba(188,140,255,.1);color:var(--purple);border-radius:4px;padding:2px 5px;font-size:9px;font-family:var(--mono)}
.comp-section{margin-bottom:18px}
.paction{background:rgba(248,81,73,.06);border:1px solid rgba(248,81,73,.2);border-radius:6px;padding:9px 13px;margin-bottom:7px;font-size:12px;line-height:1.6}
.ctrl-tbl{width:100%;border-collapse:collapse;font-size:11px}
.ctrl-tbl th{text-align:left;padding:7px 10px;font-size:9px;text-transform:uppercase;color:var(--muted);border-bottom:1px solid var(--border)}
.ctrl-tbl td{padding:7px 10px;border-bottom:1px solid rgba(48,54,61,.5);vertical-align:top}
.ctrl-tbl tr:hover td{background:rgba(255,255,255,.02)}
.pkg-result{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:10px 13px;margin-bottom:7px;display:flex;align-items:center;gap:10px}
.pkg-name{font-family:var(--mono);font-size:12px;flex:1}.pkg-score{font-size:14px;font-weight:700}
.pkg-err{font-size:11px;color:var(--muted)}
.req-area{width:100%;min-height:100px;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:var(--mono);font-size:11px;padding:8px;outline:none;resize:vertical;margin-bottom:8px}
.req-area:focus{border-color:var(--accent)}
.sec-title{font-size:11px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:10px;margin-top:18px;padding-bottom:6px;border-bottom:1px solid var(--border)}
.export-grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-bottom:18px}
.export-btn{padding:12px;border-radius:var(--radius);border:1px solid var(--border);background:var(--surface);color:var(--text);font-size:12px;cursor:pointer;text-align:center;transition:all .15s}
.export-btn:hover{border-color:var(--accent);color:var(--accent);background:rgba(88,166,255,.05)}
.export-icon{font-size:20px;display:block;margin-bottom:5px}
.diff-old{color:var(--red)}.diff-new{color:var(--green)}
.health-item{display:flex;align-items:flex-start;gap:10px;padding:10px 13px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:7px}
.hi-icon{font-size:14px;flex-shrink:0;margin-top:1px}
.hi-label{font-size:12px;font-weight:600;margin-bottom:2px}
.hi-detail{font-size:11px;color:var(--muted);line-height:1.5}
.cbox{display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:250px;gap:12px}
.spinner{width:32px;height:32px;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .7s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.lmsg{color:var(--muted);font-size:12px}
.errbox{max-width:520px;background:rgba(248,81,73,.07);border:1px solid rgba(248,81,73,.3);border-radius:var(--radius);padding:14px 18px;margin:36px auto}
.errtitle{font-weight:700;color:var(--red);margin-bottom:7px}.errbody{font-size:11px;line-height:1.7;white-space:pre-wrap;word-break:break-word;font-family:var(--mono)}
.demo-out{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:14px;font-family:var(--mono);font-size:11px;line-height:1.8;overflow-x:auto}
::-webkit-scrollbar{width:4px;height:4px}::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px}::-webkit-scrollbar-thumb:hover{background:var(--muted)}
</style>
</head>
<body>
<div class="topbar">
  <div class="logo">AgentScan</div><div class="logo-sub">AI Agent Security</div>
  <div class="ts"></div><div class="vbadge">v__VERSION__</div>
</div>
<div class="layout">
<div class="sidebar">
  <div class="sb-block">
    <div class="sb-label">Scan</div>
    <div class="mode-tabs">
      <button class="mode-tab active" onclick="setMode(this,'github')">GitHub</button>
      <button class="mode-tab" onclick="setMode(this,'file')">Upload File</button>
      <button class="mode-tab" onclick="setMode(this,'local')">Local Path</button>
      <button class="mode-tab" onclick="setMode(this,'url')">URL / MCP</button>
    </div>

    <!-- GitHub -->
    <div id="m-github">
      <div class="inp-row">
        <input class="txt-in" id="gh-in" placeholder="github.com/user/repo" onkeydown="if(event.key==='Enter')runScan()">
        <button class="icon-btn" onclick="pasteClipTo('gh-in')" title="Paste">&#128203;</button>
      </div>
      <div class="hint">Works with any public repo or subfolder:<br>github.com/user/repo/tree/main/agents/</div>
    </div>

    <!-- File upload -->
    <div id="m-file" style="display:none">
      <div class="drop-zone" id="dz" onclick="triggerPick()"
           ondragover="event.preventDefault();this.classList.add('over')"
           ondragleave="this.classList.remove('over')"
           ondrop="handleDrop(event)">
        <div class="dz-icon">&#128194;</div>
        <div class="dz-t">Drop files or click to browse</div>
        <div class="dz-h">.py, .yaml, .json, .yml — auto-detected</div>
      </div>
      <input type="file" id="fpick" multiple accept=".py,.yaml,.yml,.json" style="display:none" onchange="handlePick(event)">
      <div class="det-badge" id="det-badge"><span id="det-type"></span></div>
      <div class="hint" id="file-hint">Select one file or multiple files from the same project</div>
    </div>

    <!-- Local path -->
    <div id="m-local" style="display:none">
      <div class="inp-row">
        <input class="txt-in" id="lp-in" placeholder="C:\projects\my-agent\" oninput="onLocalChange()" onkeydown="if(event.key==='Enter')runScan()">
        <button class="icon-btn" onclick="pasteClipTo('lp-in')" title="Paste from clipboard">&#128203;</button>
      </div>
      <div class="det-badge" id="lp-badge"><span id="lp-type"></span></div>
      <div class="hint">In Explorer: click the address bar, copy the path, paste here</div>
    </div>

    <!-- URL / MCP -->
    <div id="m-url" style="display:none">
      <div class="inp-row">
        <input class="txt-in" id="url-in" placeholder="https://mcp.example.com" onkeydown="if(event.key==='Enter')runScan()">
        <button class="icon-btn" onclick="pasteClipTo('url-in')" title="Paste">&#128203;</button>
      </div>
      <div class="hint">Scans a live MCP server endpoint</div>
    </div>

    <button class="scan-btn" id="scan-btn" onclick="runScan()">Scan</button>
    <button class="demo-btn" onclick="runDemo()">Run built-in demo (12 scenarios)</button>
  </div>

  <div class="sb-block" style="flex:1">
    <div class="sb-label">Recent scans</div>
    <div id="hist-list"><div class="hint" style="text-align:center;padding:10px 0">No scans yet</div></div>
  </div>
</div>

<div class="content" id="content">
  <div class="welcome">
    <div class="welcome-icon">&#128737;</div>
    <h2>Find attack paths before attackers do</h2>
    <p>Upload files, paste a GitHub URL, or enter a path.<br>AgentScan auto-detects the type and shows the full attack chain.</p>
    <div class="wcards">
      <div class="wcard"><div class="wcard-n">Source code</div><div class="wcard-t">Python agents</div><div class="wcard-d">LangChain, CrewAI, AutoGen, PydanticAI, LlamaIndex + 12 more</div></div>
      <div class="wcard"><div class="wcard-n">Config files</div><div class="wcard-t">YAML / JSON</div><div class="wcard-d">Agent configs, Dify, n8n, Flowise, MCP server manifests</div></div>
      <div class="wcard"><div class="wcard-n">Supply chain</div><div class="wcard-t">Packages &amp; models</div><div class="wcard-d">PyPI, npm, HuggingFace models and datasets</div></div>
    </div>
  </div>
</div>
</div>

<script>__D3__</script>
<script>
// ── State ──────────────────────────────────────────────────────
let mode='github', pkgType='pypi', history=JSON.parse(localStorage.getItem('ash')||'[]');
let curResult=null, curTarget=null, curTab='summary', graphData=null, compData=null;
let uploadedFiles=[];

// ── Helpers ──────────────────────────────────────────────────────
const esc=s=>String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const rc=s=>s>=70?'var(--red)':s>=40?'var(--orange)':s>=10?'#e3b341':'var(--green)';
const rl=s=>s>=70?'CRITICAL':s>=40?'HIGH':s>=10?'MEDIUM':'LOW';
const dc=s=>s>=70?'#f85149':s>=40?'#e3b341':s>=10?'#e3b341':'#3fb950';
const $=id=>document.getElementById(id);
const showC=h=>$('content').innerHTML=h;
const loading=m=>showC('<div class="cbox"><div class="spinner"></div><div class="lmsg">'+esc(m||'Scanning...')+'</div></div>');
const showErr=m=>showC('<div class="errbox"><div class="errtitle">Error</div><div class="errbody">'+esc(m)+'</div></div>');

// ── Mode switching ──────────────────────────────────────────────
function setMode(btn,m){
  document.querySelectorAll('.mode-tab').forEach(t=>t.classList.remove('active'));
  btn.classList.add('active'); mode=m;
  ['github','file','local','url'].forEach(x=>{const el=$('m-'+x);if(el)el.style.display=x===m?'':'none'});
}

async function pasteClipTo(id){
  try{const t=await navigator.clipboard.readText();$(id).value=t.trim();if(id==='lp-in')onLocalChange();}
  catch(e){alert('Use Ctrl+V to paste');}
}

// ── File upload ──────────────────────────────────────────────────
function triggerPick(){$('fpick').click();}

function handleDrop(ev){
  ev.preventDefault();$('dz').classList.remove('over');
  const files=[...ev.dataTransfer.files];
  if(files.length)processFiles(files);
}

function handlePick(ev){
  const files=[...ev.target.files];
  if(files.length)processFiles(files);
}

async function processFiles(files){
  uploadedFiles=[];
  const supported=['.py','.yaml','.yml','.json'];
  const valid=files.filter(f=>supported.some(ext=>f.name.endsWith(ext)));
  if(!valid.length){$('file-hint').textContent='No supported files selected (.py, .yaml, .yml, .json)';return;}
  for(const f of valid){
    const content=await f.text();
    uploadedFiles.push({name:f.name,content});
  }
  const badge=$('det-badge'), dt=$('det-type');
  const names=valid.map(f=>f.name).join(', ');
  dt.textContent=valid.length===1?valid[0].name:valid.length+' files selected';
  badge.classList.add('show');
  $('file-hint').textContent=valid.length===1?'1 file ready to scan':valid.length+' files ready to scan';
}

// ── Local path auto-detect ──────────────────────────────────────
function onLocalChange(){
  const v=$('lp-in').value.trim();
  const badge=$('lp-badge'),dt=$('lp-type');
  if(!v){badge.classList.remove('show');return;}
  let d='';
  if(v.endsWith('.py'))d='Python source file';
  else if(v.endsWith('.yaml')||v.endsWith('.yml')||v.endsWith('.json'))d='Config / manifest file';
  else if(v.endsWith('\\')||v.endsWith('/')||!v.includes('.'))d='Folder (source scan)';
  if(d){dt.textContent=d;badge.classList.add('show');}
  else badge.classList.remove('show');
}

// ── Get target from active mode ──────────────────────────────────
function getTarget(){
  if(mode==='github')return $('gh-in').value.trim();
  if(mode==='local')return $('lp-in').value.trim();
  if(mode==='url')return $('url-in').value.trim();
  if(mode==='file')return uploadedFiles.length?'__upload__':'';
  return '';
}

// ── Scan ──────────────────────────────────────────────────────────
async function runScan(){
  const target=getTarget();
  if(!target){
    const hints={github:'Paste a GitHub URL (e.g. github.com/user/repo)',file:'Select files using the file picker or drop zone',local:'Enter a file or folder path',url:'Enter an MCP server URL'};
    showErr(hints[mode]||'Enter a target to scan');return;
  }
  loading(mode==='github'?'Cloning and scanning...':'Scanning '+target+'...');
  setBusy(true);
  try{
    let resp,result;
    if(mode==='file'&&uploadedFiles.length){
      if(uploadedFiles.length===1){
        resp=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},
          body:JSON.stringify({target:'__upload__',file_content:uploadedFiles[0].content,filename:uploadedFiles[0].name})});
      } else {
        resp=await fetch('/api/upload_dir',{method:'POST',headers:{'Content-Type':'application/json'},
          body:JSON.stringify({files:uploadedFiles})});
      }
    } else {
      resp=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target})});
    }
    result=await resp.json();
    if(result.error){showErr(result.error+(result.detail?'\n\n'+result.detail:''));return;}
    curResult=result;curTarget=target;
    addHist(target,result.risk_score||0,result.type||result.scanner_type);
    renderResults(result,target);
    graphData=null;compData=null;
    loadGraph(target);loadCompliance(target);
  }catch(e){showErr(e.message);}
  finally{setBusy(false);}
}

async function runDemo(){
  loading('Running 12 attack scenarios...');setBusy(true);
  try{
    const r=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:'__demo__',force_type:'demo'})});
    const d=await r.json();renderDemo(d.output||d.error||'No output');
  }catch(e){showErr(e.message);}
  finally{setBusy(false);}
}

function setBusy(b){const btn=$('scan-btn');btn.disabled=b;btn.textContent=b?'Scanning...':'Scan';}

// ── History ──────────────────────────────────────────────────────
function addHist(target,score,type){
  const prev=history.find(h=>h.target===target);
  const diff=prev?score-prev.score:null;
  history=history.filter(h=>h.target!==target);
  history.unshift({target,score,type,diff,time:new Date().toLocaleTimeString()});
  if(history.length>20)history.pop();
  localStorage.setItem('ash',JSON.stringify(history));
  renderHist();
}

function renderHist(){
  const el=$('hist-list');
  if(!history.length){el.innerHTML='<div class="hint" style="text-align:center;padding:10px 0">No scans yet</div>';return;}
  el.innerHTML=history.map((h,i)=>{
    const diffHtml=h.diff!==null&&h.diff!==0?'<span class="hdiff" style="color:'+(h.diff>0?'var(--red)':'var(--green)')+'">'+( h.diff>0?'+':'')+h.diff+'</span>':'';
    return '<div class="hist-item" onclick="replayHist('+i+')" title="'+esc(h.target)+'"><div class="hdot" style="background:'+dc(h.score)+'"></div><div class="hpath">'+esc(h.target.split(/[\/\\]/).pop()||h.target)+'</div><div class="htime">'+h.time+'</div>'+diffHtml+'</div>';
  }).join('');
}

async function replayHist(i){
  const h=history[i];if(!h)return;
  if(h.target.includes('github.com')){$('gh-in').value=h.target;setMode(document.querySelector('[onclick*="github"]'),'github');}
  else{$('lp-in').value=h.target;setMode(document.querySelector('[onclick*="local"]'),'local');onLocalChange();}
  await runScan();
}

// ── Render results ────────────────────────────────────────────────
function renderResults(d,target){
  const score=d.risk_score||0,findings=d.findings||[],paths=d.attack_paths||[];
  const rep=findings.filter(f=>f.severity!=='INFO');
  const cnt={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,INFO:0};
  findings.forEach(f=>{if(cnt[f.severity]!==undefined)cnt[f.severity]++;});
  const tl=(d.type||d.scanner_type||'').replace('_scanner','').replace(/_/g,' ');
  const hasMcp=d.mcp_manifests_found&&d.mcp_manifests_found.length;

  let h='<div class="rw">';
  h+='<div class="rhead"><div class="rtarget">'+esc(target)+'</div><div class="rtype">'+esc(tl)+'</div>';
  if(hasMcp)h+='<div class="rtype" style="background:rgba(188,140,255,.1);color:var(--purple)">+MCP</div>';
  h+='<div class="act-btns"><button class="btn-sm" onclick="showTab(\'export\')">Export</button></div></div>';

  // Tabs
  h+='<div class="tabs">';
  h+='<div class="tab active" data-tab="summary" onclick="showTab(\'summary\')">Summary</div>';
  h+='<div class="tab" data-tab="graph" onclick="showTab(\'graph\')">Attack Graph<span class="tbadge">'+paths.length+'</span></div>';
  h+='<div class="tab" data-tab="findings" onclick="showTab(\'findings\')">Findings<span class="tbadge">'+rep.length+'</span></div>';
  h+='<div class="tab" data-tab="compliance" onclick="showTab(\'compliance\')">Compliance</div>';
  h+='<div class="tab" data-tab="supply" onclick="showTab(\'supply\')">Supply Chain</div>';
  h+='<div class="tab" data-tab="health" onclick="showTab(\'health\')">Health</div>';
  h+='<div class="tab" data-tab="export" onclick="showTab(\'export\')">Export</div>';
  h+='</div>';

  // ── SUMMARY ──
  h+='<div id="t-summary">';
  h+='<div class="metrics">';
  h+='<div class="metric"><div class="mlbl">Risk Score</div><div class="mval" style="color:'+rc(score)+'">'+score+'<span style="font-size:13px;color:var(--muted)">/100</span></div><div class="msub">'+rl(score)+'</div><div class="rbar"><div class="rfill" id="rfill" style="width:0%;background:'+rc(score)+'"></div></div></div>';
  h+='<div class="metric"><div class="mlbl">Critical</div><div class="mval" style="color:var(--red)">'+cnt.CRITICAL+'</div><div class="msub">'+cnt.HIGH+' high</div></div>';
  h+='<div class="metric"><div class="mlbl">Attack Paths</div><div class="mval" style="color:'+(paths.length?'var(--red)':'var(--green)')+'">'+paths.length+'</div><div class="msub">complete chains</div></div>';
  h+='<div class="metric"><div class="mlbl">Findings</div><div class="mval">'+rep.length+'</div><div class="msub">'+cnt.MEDIUM+' med  '+cnt.LOW+' low</div></div>';
  h+='</div>';
  // Severity pills
  h+='<div class="sev-strip">';
  ['CRITICAL','HIGH','MEDIUM','LOW','INFO'].forEach(s=>{if(cnt[s])h+='<div class="sev-pill sp-'+s+'"><span class="sev-n">'+cnt[s]+'</span>'+s+'</div>';});
  h+='</div>';
  // Compliance posture placeholder
  h+='<div id="posture-card" class="posture-card"><div class="lmsg">Loading compliance posture...</div></div>';
  // Top paths preview
  if(paths.length){
    h+='<div class="sec-title" style="font-size:11px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:10px;margin-top:14px">Top Attack Paths</div>';
    paths.slice(0,3).forEach(p=>{
      const steps=(p.steps||[]).slice(0,4).map(s=>{const t=s.title||'';return t.includes("'")?t.split("'")[1]:t.substring(0,18);}).filter(Boolean);
      h+='<div class="pcard" onclick="showTab(\'graph\')" style="margin-bottom:7px"><div class="ptitle">'+esc(p.title)+'</div>';
      if(steps.length)h+='<div class="pchain">Prompt &rarr; '+steps.map(esc).join(' &rarr; ')+'</div>';
      h+='<div class="pentry">Entry: '+esc(p.entry_point||'')+' &nbsp; '+esc((p.mitre_atlas||[]).join(', '))+'</div></div>';
    });
  }
  h+='</div>';

  // ── GRAPH ──
  h+='<div id="t-graph" style="display:none">';
  h+='<div class="graph-wrap"><svg id="gsvg"><text x="50%" y="50%" fill="#8b949e" font-size="12" text-anchor="middle" dominant-baseline="middle">Loading graph...</text></svg></div>';
  h+='<div class="glegend">';
  [['#f85149','Entry / Crown Jewel'],['#bc8cff','Agent / MCP'],['#58a6ff','Tool'],['#e3b341','Resource'],['#3fb950','Network']].forEach(([c,l])=>h+='<div class="gli"><div class="gldot" style="background:'+c+'"></div>'+esc(l)+'</div>');
  h+='</div><div class="path-grid" id="gpaths"></div></div>';

  // ── FINDINGS ──
  h+='<div id="t-findings" style="display:none">';
  if(!rep.length){h+='<div class="cbox" style="min-height:160px"><div style="color:var(--green);font-size:13px">No reportable findings</div></div>';}
  else{
    h+='<div class="fbar"><button class="fchip active" onclick="filterF(this,\'ALL\')">All ('+rep.length+')</button>';
    ['CRITICAL','HIGH','MEDIUM','LOW'].forEach(s=>{if(cnt[s])h+='<button class="fchip" onclick="filterF(this,\''+s+'\')">'+s+' ('+cnt[s]+')</button>';});
    h+='</div><div id="flist">';
    rep.forEach((f,i)=>{
      h+='<div class="fcard" data-sev="'+f.severity+'" id="fc'+i+'"><div class="fhead" onclick="toggleF('+i+')">';
      h+='<span class="schip sc-'+f.severity+'">'+f.severity+'</span><span class="ftitle">'+esc(f.title)+'</span><span class="chev">&#9654;</span></div>';
      h+='<div class="fbody">';
      if(f.explanation)h+='<div class="fslbl">What is happening</div><div class="fstxt">'+esc(f.explanation)+'</div>';
      if(f.impact)h+='<div class="fslbl">Impact</div><div class="fstxt">'+esc(f.impact)+'</div>';
      if(f.remediation)h+='<div class="ffix"><strong>Fix:</strong> '+esc(f.remediation)+'</div>';
      if(f.evidence&&f.evidence.length)h+='<div class="fevid">'+f.evidence.map(e=>esc(e.source+': '+e.observed_value)).join('<br>')+'</div>';
      if(f.mitre_atlas&&f.mitre_atlas.length)h+='<div class="mtags">'+f.mitre_atlas.map(m=>'<span class="mtag">'+m+'</span>').join('')+'</div>';
      h+='</div></div>';
    });
    h+='</div>';
  }
  h+='</div>';

  // ── COMPLIANCE ──
  h+='<div id="t-compliance" style="display:none"><div id="comp-content"><div class="cbox" style="min-height:160px"><div class="spinner"></div><div class="lmsg">Loading compliance map...</div></div></div></div>';

  // ── SUPPLY CHAIN ──
  h+='<div id="t-supply" style="display:none">';
  h+='<div class="sec-title">Scan a package</div>';
  h+='<div class="pkg-tabs"><button class="pkg-tab active" onclick="setPkg(this,\'pypi\')">PyPI</button><button class="pkg-tab" onclick="setPkg(this,\'npm\')">npm</button><button class="pkg-tab" onclick="setPkg(this,\'hf\')">HuggingFace</button><button class="pkg-tab" onclick="setPkg(this,\'dataset\')">Dataset</button></div>';
  h+='<div class="inp-row" style="margin-bottom:10px"><input class="txt-in" id="pkg-in" placeholder="e.g. langchain" onkeydown="if(event.key===\'Enter\')scanPkg()"><button class="icon-btn" onclick="scanPkg()">&#8594;</button></div>';
  h+='<div class="sec-title">Or paste requirements.txt / package.json</div>';
  h+='<textarea class="req-area" id="req-area" placeholder="Paste requirements.txt or package.json contents here..."></textarea>';
  h+='<button class="btn-sm" onclick="scanReqs()" style="margin-bottom:14px">Scan all dependencies</button>';
  h+='<div id="supply-results"></div></div>';

  // ── HEALTH ──
  h+='<div id="t-health" style="display:none"><div id="health-content"><div class="cbox" style="min-height:160px"><div class="spinner"></div><div class="lmsg">Running health check...</div></div></div></div>';

  // ── EXPORT ──
  h+='<div id="t-export" style="display:none">';
  h+='<div class="sec-title">Export scan results</div>';
  h+='<div class="export-grid">';
  h+='<button class="export-btn" onclick="copyJSON()"><span class="export-icon">&#128196;</span>Copy JSON<br><small style="color:var(--muted)">Full scan data</small></button>';
  h+='<button class="export-btn" onclick="copyMarkdown()"><span class="export-icon">&#128221;</span>Copy Markdown<br><small style="color:var(--muted)">For tickets/docs</small></button>';
  h+='<button class="export-btn" onclick="downloadHTML()"><span class="export-icon">&#127760;</span>Download HTML<br><small style="color:var(--muted)">Self-contained report</small></button>';
  h+='</div>';
  // Diff section
  if(history.length>1){
    const prev=history.find(h2=>h2.target===target&&h2.time!==history[0].time);
    if(prev){
      h+='<div class="sec-title">Compare with previous scan</div>';
      const diff=score-(prev.score||0);
      const diffColor=diff>0?'var(--red)':'var(--green)';
      h+='<div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:14px;font-size:13px">';
      h+='Previous score: <strong>'+prev.score+'</strong> &nbsp; Current: <strong>'+score+'</strong> &nbsp; ';
      h+='Change: <strong style="color:'+diffColor+'">'+(diff>0?'+':'')+diff+'</strong></div>';
    }
  }
  h+='</div>';

  h+='</div>';
  showC(h);
  setTimeout(()=>{const el=$('rfill');if(el)el.style.width=score+'%';},100);
  renderHist();
}

// ── Tab switching ──────────────────────────────────────────────────
function showTab(tabId){
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('[id^="t-"]').forEach(t=>t.style.display='none');
  const tab=document.querySelector('[data-tab="'+tabId+'"]');
  if(tab)tab.classList.add('active');
  const pane=$('t-'+tabId);
  if(pane)pane.style.display='';
  curTab=tabId;
  if(tabId==='graph'&&graphData)renderGraph(graphData);
  if(tabId==='health'&&curTarget)loadHealth(curTarget);
}

// ── Graph ──────────────────────────────────────────────────────────
async function loadGraph(target){
  try{
    const r=await fetch('/api/graph',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target})});
    const d=await r.json();
    if(!d.error){graphData=d;if(curTab==='graph')renderGraph(d);}
    else{const s=$('gsvg');if(s)s.innerHTML='<text x="50%" y="50%" fill="#8b949e" font-size="12" text-anchor="middle" dominant-baseline="middle">'+esc(d.error)+'</text>';}
  }catch(e){}
}

function renderGraph(data){
  const svgEl=document.getElementById('gsvg');
  if(!svgEl||!data)return;
  const W=svgEl.clientWidth||800,H=svgEl.clientHeight||400;
  svgEl.innerHTML='';
  const NC={'entry_point':'#f85149','crown_jewel':'#f85149','agent':'#bc8cff','mcp_server':'#bc8cff','tool':'#58a6ff','resource':'#e3b341','data_store':'#e3b341','network':'#3fb950','external':'#3fb950'};
  const gc=t=>NC[t]||'#8b949e';
  const nodes=data.nodes.map(n=>({...n}));
  const links=data.edges.map(e=>({...e}));
  const svg=d3.select('#gsvg');
  const defs=svg.append('defs');
  ['default','red','blue'].forEach(id=>{
    defs.append('marker').attr('id','arr'+id).attr('viewBox','0 -4 10 8').attr('refX',24).attr('refY',0).attr('markerWidth',5).attr('markerHeight',5).attr('orient','auto')
      .append('path').attr('d','M0,-4L10,0L0,4').attr('fill',id==='red'?'#f85149':id==='blue'?'#58a6ff':'#30363d');
  });
  const zoom=d3.zoom().scaleExtent([.2,3]).on('zoom',e=>g.attr('transform',e.transform));
  svg.call(zoom);
  const g=svg.append('g');
  const sim=d3.forceSimulation(nodes)
    .force('link',d3.forceLink(links).id(d=>d.id).distance(120))
    .force('charge',d3.forceManyBody().strength(-320))
    .force('center',d3.forceCenter(W/2,H/2))
    .force('collision',d3.forceCollide(28));
  const link=g.selectAll('.e').data(links).enter().append('line')
    .attr('stroke','#30363d').attr('stroke-width',1.5).attr('marker-end','url(#arrdefault)');
  const node=g.selectAll('.n').data(nodes).enter().append('g').attr('class','n')
    .call(d3.drag().on('start',(e,d)=>{if(!e.active)sim.alphaTarget(.3).restart();d.fx=d.x;d.fy=d.y;})
                   .on('drag',(e,d)=>{d.fx=e.x;d.fy=e.y;})
                   .on('end',(e,d)=>{if(!e.active)sim.alphaTarget(0);d.fx=null;d.fy=null;}));
  node.append('circle').attr('r',d=>d.is_crown_jewel||d.attacker_controlled?20:16)
    .attr('fill',d=>gc(d.type)).attr('fill-opacity',.85)
    .attr('stroke',d=>d.is_crown_jewel?'#f85149':d.attacker_controlled?'#e3b341':'#0d1117').attr('stroke-width',2);
  node.append('text').attr('text-anchor','middle').attr('dy','4px').attr('font-size','8px')
    .attr('fill','#e6edf3').attr('pointer-events','none')
    .text(d=>(d.label||d.id||'').substring(0,12));
  node.append('title').text(d=>(d.label||d.id)+' ['+d.type+']');
  sim.on('tick',()=>{
    link.attr('x1',d=>d.source.x).attr('y1',d=>d.source.y).attr('x2',d=>d.target.x).attr('y2',d=>d.target.y);
    node.attr('transform',d=>'translate('+d.x+','+d.y+')');
  });
  // Path list
  const gp=$('gpaths');
  if(gp&&data.paths&&data.paths.length){
    gp.innerHTML=data.paths.map((p,i)=>'<div class="pcard" id="gp'+i+'" onclick="hlPath('+i+')"><div class="ptitle">'+esc(p.title)+'</div><div class="pchain">'+esc((p.nodes||[]).join(' -> '))+'</div><div class="pentry">'+esc(p.entry_point||'')+'  '+(p.exploitability?'Exploitability: '+(p.exploitability*100).toFixed(0)+'%':'')+'</div></div>').join('');
  } else if(gp) {
    gp.innerHTML='<div style="color:var(--muted);font-size:12px;grid-column:1/-1;padding:10px 0">No attack paths found in this scan</div>';
  }
}

function hlPath(i){
  document.querySelectorAll('.pcard').forEach(c=>c.classList.remove('sel'));
  const c=$('gp'+i);if(c)c.classList.add('sel');
}

// ── Compliance ─────────────────────────────────────────────────────
async function loadCompliance(target){
  try{
    const r=await fetch('/api/compliance',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target})});
    const d=await r.json();
    if(!d.error){compData=d;if(curTab==='compliance')renderCompliance(d);updatePosture(d);}
    else{const el=$('comp-content');if(el)el.innerHTML='<div class="hint" style="padding:14px">Compliance map not available: '+esc(d.error)+'</div>';}
  }catch(e){}
}

function updatePosture(d){
  const pc=$('posture-card');if(!pc)return;
  const p=d.overall_posture||'UNKNOWN';
  const cls=p.toLowerCase().replace(/[-\s]/g,'-');
  pc.innerHTML='<div><div class="plbl">Compliance Posture</div><div class="pval p-'+cls+'">'+esc(p)+'</div></div>'+
    '<div class="psep"></div>'+
    '<div><div class="plbl">Frameworks</div><div class="fw-chips">'+(d.frameworks||[]).slice(0,8).map(f=>'<span class="fw-chip">'+esc(f)+'</span>').join('')+'</div></div>';
}

function renderCompliance(d){
  const el=$('comp-content');if(!el)return;
  const p=d.overall_posture||'UNKNOWN';
  const cls=p.toLowerCase().replace(/[-\s]/g,'-');
  let h='<div class="comp-section">';
  h+='<div style="font-size:22px;font-weight:700;margin-bottom:4px" class="p-'+cls+'">'+esc(p)+'</div>';
  h+='<div style="font-size:11px;color:var(--muted);margin-bottom:14px">Overall compliance posture</div>';
  const fws=d.frameworks||[];
  if(fws.length)h+='<div class="fw-chips" style="margin-bottom:14px">'+fws.map(f=>'<span class="fw-chip">'+esc(f)+'</span>').join('')+'</div>';
  // Control summary
  const cs=d.control_summary||{};
  if(Object.keys(cs).length){
    h+='<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px">';
    Object.entries(cs).forEach(([fw,count])=>h+='<div style="background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:6px 12px;font-size:11px"><span style="color:var(--muted)">'+esc(fw)+'</span> <span style="font-weight:700">'+count+'</span></div>');
    h+='</div>';
  }
  h+='</div>';
  const gaps=d.priority_gaps||[];
  if(gaps.length){
    h+='<div style="font-size:11px;font-weight:700;color:var(--red);margin-bottom:8px;text-transform:uppercase;letter-spacing:.4px">Priority Actions</div>';
    gaps.forEach(g=>h+='<div class="paction">'+esc(g)+'</div>');
  }
  const mappings=d.mappings||[];
  if(mappings.length){
    h+='<div style="font-size:11px;font-weight:700;color:var(--muted);margin:16px 0 8px;text-transform:uppercase;letter-spacing:.4px">Finding to Control Mapping</div>';
    h+='<table class="ctrl-tbl"><thead><tr><th>Finding</th><th>Sev</th><th>Framework</th><th>Control</th><th>Obligation</th></tr></thead><tbody>';
    mappings.forEach(m=>{
      const ctrls=m.controls||[];
      ctrls.forEach((c,i)=>{
        h+='<tr>';
        if(i===0){h+='<td rowspan="'+ctrls.length+'" style="max-width:200px">'+esc(m.finding_title)+'</td>';h+='<td rowspan="'+ctrls.length+'"><span class="schip sc-'+m.finding_severity+'">'+m.finding_severity+'</span></td>';}
        h+='<td style="white-space:nowrap">'+esc(c.framework)+'</td><td>'+esc(c.control_id)+' '+esc(c.control_name)+'</td><td style="font-size:10px;color:var(--muted);max-width:200px">'+esc(c.obligation)+'</td></tr>';
      });
    });
    h+='</tbody></table>';
  }
  el.innerHTML=h;
}

// ── Supply chain ───────────────────────────────────────────────────
let pkgTypeVal='pypi';
function setPkg(btn,t){document.querySelectorAll('.pkg-tab').forEach(b=>b.classList.remove('active'));btn.classList.add('active');pkgTypeVal=t;const hints={pypi:'e.g. langchain',npm:'e.g. @langchain/core',hf:'e.g. microsoft/phi-3',dataset:'e.g. openai/gsm8k'};$('pkg-in').placeholder=hints[t]||'package name';}

async function scanPkg(){
  const pkg=$('pkg-in').value.trim();if(!pkg)return;
  $('supply-results').innerHTML='<div class="cbox" style="min-height:100px"><div class="spinner"></div></div>';
  const r=await fetch('/api/supply_chain',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:pkgTypeVal+':'+pkg})});
  const d=await r.json();
  renderSupply(d.packages||[]);
}

async function scanReqs(){
  const content=$('req-area').value.trim();if(!content)return;
  const pmHint=content.startsWith('{')&&content.includes('"dependencies"')?'npm':'pypi';
  $('supply-results').innerHTML='<div class="cbox" style="min-height:100px"><div class="spinner"></div><div class="lmsg">Scanning dependencies...</div></div>';
  const r=await fetch('/api/supply_chain',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({content,pkg_manager:pmHint})});
  const d=await r.json();
  renderSupply(d.packages||[]);
}

function renderSupply(pkgs){
  if(!pkgs.length){$('supply-results').innerHTML='<div class="hint">No packages found</div>';return;}
  $('supply-results').innerHTML=pkgs.map(p=>{
    const sc=p.risk_score||0;
    return '<div class="pkg-result"><div class="pkg-name">'+esc(p.package_name||p.target||'')+'</div>'+
      (p.error?'<div class="pkg-err">'+esc(p.error)+'</div>':'<div class="pkg-score" style="color:'+rc(sc)+'">'+sc+'/100</div>')+
      '</div>';
  }).join('');
}

// ── Health ─────────────────────────────────────────────────────────
async function loadHealth(target){
  const el=$('health-content');if(!el)return;
  const path=target.includes('github.com')?'.':target;
  try{
    const r=await fetch('/api/doctor',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path})});
    const d=await r.json();
    if(d.error){el.innerHTML='<div class="hint">'+esc(d.error)+'</div>';return;}
    const icons={ok:'&#9989;',warn:'&#9888;&#65039;',info:'&#8505;&#65039;',error:'&#10060;'};
    el.innerHTML='<div style="margin-bottom:8px;font-size:12px;color:var(--muted)">Environment health check for: <strong>'+esc(path)+'</strong></div>'+
      (d.results||[]).map(r=>'<div class="health-item"><div class="hi-icon">'+(icons[r.severity]||'&#8505;')+'</div><div><div class="hi-label">'+esc(r.label)+'</div><div class="hi-detail">'+esc(r.detail||'')+(r.suggested_command?'<br><span style="font-family:var(--mono);font-size:10px;color:var(--accent)">'+esc(r.suggested_command)+'</span>':'')+'</div></div></div>').join('');
  }catch(e){el.innerHTML='<div class="hint">'+esc(e.message)+'</div>';}
}

// ── Findings interactions ──────────────────────────────────────────
function toggleF(i){$('fc'+i).classList.toggle('open');}
function filterF(btn,sev){
  document.querySelectorAll('.fchip').forEach(c=>c.classList.remove('active'));btn.classList.add('active');
  document.querySelectorAll('.fcard').forEach(c=>c.style.display=(sev==='ALL'||c.dataset.sev===sev)?'':'none');
}

// ── Export ─────────────────────────────────────────────────────────
function copyJSON(){if(!curResult)return;navigator.clipboard.writeText(JSON.stringify(curResult,null,2)).then(()=>alert('JSON copied'));}
function copyMarkdown(){
  if(!curResult)return;
  const d=curResult;
  let md='# AgentScan Report: '+(curTarget||'')+'\n\n**Risk Score:** '+(d.risk_score||0)+'/100\n\n';
  (d.attack_paths||[]).forEach(p=>{md+='## Attack Path: '+p.title+'\n**Entry:** '+p.entry_point+'\n\n';});
  (d.findings||[]).filter(f=>f.severity!=='INFO').forEach(f=>{md+='### ['+f.severity+'] '+f.title+'\n'+f.explanation+'\n\n**Fix:** '+f.remediation+'\n\n';});
  navigator.clipboard.writeText(md).then(()=>alert('Markdown copied'));
}
function downloadHTML(){
  if(!curResult)return;
  const blob=new Blob([JSON.stringify(curResult,null,2)],{type:'application/json'});
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='agentscan_report.json';a.click();
}

// ── Demo ────────────────────────────────────────────────────────────
function renderDemo(output){
  const lines=(output||'').split('\n');
  let h='<div class="rw"><div class="rhead"><div class="rtarget">Built-in Demo -- 12 Attack Scenarios</div></div><div class="demo-out">';
  lines.forEach(l=>{
    const clean=l.replace(/\x1b\[[0-9;]*m/g,'');
    const col=clean.includes('[OK]')||clean.includes('PASS')?'var(--green)':clean.includes('[X]')||clean.includes('FAIL')?'var(--red)':clean.includes('Risk')?'var(--accent)':'var(--muted)';
    h+='<div style="color:'+col+'">'+esc(clean)+'</div>';
  });
  h+='</div></div>';showC(h);
}

// ── Init ─────────────────────────────────────────────────────────────
renderHist();
</script>
</body>
</html>
'''
