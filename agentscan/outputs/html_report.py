"""
Static HTML Dashboard Report
==============================
A single self-contained HTML file with no backend, no server, no database.
Opens directly in any browser. This is the artifact you hand to someone
after running AgentScan against their config — a polished report instead
of a wall of terminal text or a raw JSON blob.

Includes: risk score gauge, severity breakdown chart, attack paths,
full findings list with evidence, and compliance control summary if available.
"""

from __future__ import annotations
import json
from datetime import date
from pathlib import Path

from agentscan.models import ScanResult, Severity


SEVERITY_COLOURS = {
    "CRITICAL": "#A32D2D",
    "HIGH": "#BA7517",
    "MEDIUM": "#854F0B",
    "LOW": "#185FA5",
    "INFO": "#5F5E5A",
}

SEVERITY_BG = {
    "CRITICAL": "#FCEBEB",
    "HIGH": "#FAEEDA",
    "MEDIUM": "#FAEEDA",
    "LOW": "#E6F1FB",
    "INFO": "#F1EFE8",
}


def _esc(s) -> str:
    """Minimal HTML escaping."""
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def generate_html_report(
    result: ScanResult,
    output_path: str,
    title: str = "",
    organisation: str = "",
) -> str:
    """Generate a self-contained HTML dashboard report. Returns the output path."""
    output_path = str(Path(output_path).with_suffix(".html"))

    findings = result.reportable_findings
    sev_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
    sorted_findings = sorted(findings, key=lambda f: sev_order.index(f.severity) if f.severity in sev_order else 99)

    counts = {sev.value: 0 for sev in Severity}
    for f in findings:
        counts[f.severity.value] += 1

    risk_score = result.risk_score()
    risk_colour = "#A32D2D" if risk_score >= 70 else "#BA7517" if risk_score >= 40 else "#854F0B" if risk_score >= 15 else "#3B6D11"
    risk_label = "CRITICAL" if risk_score >= 70 else "HIGH" if risk_score >= 40 else "MEDIUM" if risk_score >= 15 else "LOW"

    display_title = title or result.target
    scan_date = date.today().strftime("%B %d, %Y")

    # Build findings cards HTML
    findings_html = ""
    if not sorted_findings:
        findings_html = '<div class="empty-state">No reportable findings — this configuration looks well-scoped.</div>'
    else:
        for f in sorted_findings:
            colour = SEVERITY_COLOURS.get(f.severity.value, "#5F5E5A")
            bg = SEVERITY_BG.get(f.severity.value, "#F1EFE8")
            evidence_html = ""
            for ev in f.evidence:
                val_str = str(ev.observed_value)
                if len(val_str) > 200:
                    val_str = val_str[:197] + "..."
                evidence_html += f"""
                <div class="evidence-row">
                  <span class="evidence-label">{_esc(ev.source)}</span>
                  <span class="evidence-value">{_esc(val_str)}</span>
                </div>"""

            mitre_html = ""
            if f.mitre_atlas:
                mitre_html = f'<div class="tag-row"><span class="tag-label">MITRE ATLAS</span> {" ".join(f"<code>{_esc(m)}</code>" for m in f.mitre_atlas)}</div>'

            findings_html += f"""
            <div class="finding-card" style="border-left-color: {colour}">
              <div class="finding-header">
                <span class="sev-badge" style="background:{bg};color:{colour}">{_esc(f.severity.value)}</span>
                <span class="conf-badge">confidence: {_esc(f.confidence.value)}</span>
                <h3>{_esc(f.title)}</h3>
              </div>
              <p class="finding-explanation">{_esc(f.explanation)}</p>
              <div class="finding-impact"><strong>Impact:</strong> {_esc(f.impact)}</div>
              {f'<div class="evidence-block">{evidence_html}</div>' if evidence_html else ''}
              <div class="finding-fix"><strong>Fix:</strong> {_esc(f.remediation)}</div>
              {mitre_html}
            </div>"""

    # Build attack paths HTML
    paths_html = ""
    if result.attack_paths:
        for i, p in enumerate(result.attack_paths, 1):
            chain = " &rarr; ".join(_esc(s.title.split("'")[1]) if "'" in s.title else _esc(s.title[:40]) for s in p.steps[:5])
            paths_html += f"""
            <div class="path-card">
              <div class="path-title">Path {i}: {_esc(p.title)}</div>
              <div class="path-row"><span class="path-label">Entry</span>{_esc(p.entry_point)}</div>
              <div class="path-row"><span class="path-label">Impact</span>{_esc(p.impact)}</div>
              <div class="path-chain">{chain}</div>
              {f'<div class="path-row"><span class="path-label">MITRE</span>{", ".join(_esc(m) for m in p.mitre_atlas)}</div>' if p.mitre_atlas else ''}
            </div>"""

    # Chart data
    chart_labels = ["Critical", "High", "Medium", "Low"]
    chart_values = [counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"], counts["LOW"]]
    chart_colours = ["#A32D2D", "#BA7517", "#854F0B", "#185FA5"]

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AgentScan Report — {_esc(display_title)}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
    background: #f4f3ef;
    color: #1a1a1a;
    line-height: 1.6;
  }}
  .page {{ max-width: 980px; margin: 0 auto; padding: 40px 24px 80px; }}
  header {{
    background: #14142b;
    color: #fff;
    padding: 36px 40px;
    border-radius: 14px;
    margin-bottom: 28px;
  }}
  header .brand {{ font-size: 13px; letter-spacing: 1.5px; color: #8b8fb8; text-transform: uppercase; margin-bottom: 12px; }}
  header h1 {{ font-size: 26px; font-weight: 600; margin-bottom: 6px; word-break: break-word; }}
  header .meta {{ font-size: 14px; color: #9a9dc4; }}

  .summary-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 14px;
    margin-bottom: 28px;
  }}
  .metric-card {{
    background: #fff;
    border-radius: 12px;
    padding: 20px;
    border: 1px solid #e3e1d8;
  }}
  .metric-label {{ font-size: 12px; color: #6c6a62; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; }}
  .metric-value {{ font-size: 30px; font-weight: 600; }}
  .metric-sub {{ font-size: 13px; color: #6c6a62; margin-top: 4px; }}

  .risk-bar-track {{ background: #eceae1; border-radius: 6px; height: 10px; margin-top: 12px; overflow: hidden; }}
  .risk-bar-fill {{ height: 100%; border-radius: 6px; }}

  section {{ background: #fff; border-radius: 14px; padding: 28px 32px; margin-bottom: 24px; border: 1px solid #e3e1d8; }}
  section h2 {{ font-size: 18px; font-weight: 600; margin-bottom: 18px; display: flex; align-items: center; gap: 8px; }}

  .chart-wrap {{ position: relative; height: 220px; margin-bottom: 8px; }}

  .path-card {{
    background: #fdf0f0;
    border: 1px solid #f0c8c8;
    border-radius: 10px;
    padding: 16px 18px;
    margin-bottom: 12px;
  }}
  .path-title {{ font-weight: 600; color: #791F1F; margin-bottom: 8px; }}
  .path-row {{ font-size: 13px; margin-bottom: 4px; }}
  .path-label {{ display: inline-block; min-width: 60px; color: #6c6a62; font-weight: 600; }}
  .path-chain {{ font-family: "SF Mono", Consolas, monospace; font-size: 12.5px; background: #fff; padding: 8px 10px; border-radius: 6px; margin-top: 8px; color: #993C1D; }}

  .finding-card {{
    border: 1px solid #e3e1d8;
    border-left: 4px solid;
    border-radius: 8px;
    padding: 18px 20px;
    margin-bottom: 14px;
  }}
  .finding-header {{ display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-bottom: 10px; }}
  .finding-header h3 {{ font-size: 15px; font-weight: 600; flex: 1; min-width: 200px; }}
  .sev-badge {{ font-size: 11px; font-weight: 700; padding: 3px 10px; border-radius: 5px; letter-spacing: 0.4px; }}
  .conf-badge {{ font-size: 11px; color: #6c6a62; }}
  .finding-explanation {{ font-size: 14px; color: #3d3d3a; margin-bottom: 10px; }}
  .finding-impact {{ font-size: 13.5px; margin-bottom: 10px; }}
  .finding-fix {{ font-size: 13.5px; background: #eaf3de; padding: 10px 12px; border-radius: 6px; color: #27500A; }}
  .evidence-block {{ background: #f4f3ef; border-radius: 6px; padding: 10px 12px; margin-bottom: 10px; font-size: 12.5px; }}
  .evidence-row {{ display: flex; gap: 8px; margin-bottom: 3px; }}
  .evidence-label {{ color: #6c6a62; min-width: 70px; }}
  .evidence-value {{ font-family: "SF Mono", Consolas, monospace; color: #3d3d3a; word-break: break-all; }}
  .tag-row {{ margin-top: 10px; font-size: 12px; }}
  .tag-label {{ color: #6c6a62; margin-right: 6px; }}
  .tag-row code {{ background: #f1eee4; padding: 2px 6px; border-radius: 4px; font-size: 11.5px; margin-right: 4px; }}

  .empty-state {{ text-align: center; padding: 40px; color: #3B6D11; font-size: 15px; background: #eaf3de; border-radius: 10px; }}

  .filter-bar {{ display: flex; gap: 8px; margin-bottom: 18px; flex-wrap: wrap; }}
  .filter-btn {{
    border: 1px solid #d9d6c9; background: #fff; padding: 6px 14px; border-radius: 20px;
    font-size: 12.5px; cursor: pointer; color: #3d3d3a;
  }}
  .filter-btn.active {{ background: #14142b; color: #fff; border-color: #14142b; }}

  footer {{ text-align: center; color: #8a887f; font-size: 12px; margin-top: 30px; }}
  footer a {{ color: #185FA5; text-decoration: none; }}
</style>
</head>
<body>
<div class="page">

  <header>
    <div class="brand">AgentScan Security Report</div>
    <h1>{_esc(display_title)}</h1>
    <div class="meta">{_esc(organisation + " &middot; " if organisation else "")}Scanned {scan_date} &middot; {_esc(result.scanner_type)}</div>
  </header>

  <div class="summary-grid">
    <div class="metric-card">
      <div class="metric-label">Risk score</div>
      <div class="metric-value" style="color:{risk_colour}">{risk_score}<span style="font-size:16px;color:#6c6a62">/100</span></div>
      <div class="metric-sub">{risk_label}</div>
      <div class="risk-bar-track"><div class="risk-bar-fill" style="width:{risk_score}%;background:{risk_colour}"></div></div>
    </div>
    <div class="metric-card">
      <div class="metric-label">Critical findings</div>
      <div class="metric-value" style="color:#A32D2D">{counts['CRITICAL']}</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">Attack paths</div>
      <div class="metric-value" style="color:{'#A32D2D' if result.attack_paths else '#3B6D11'}">{len(result.attack_paths)}</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">Total findings</div>
      <div class="metric-value">{len(findings)}</div>
      <div class="metric-sub">{counts['HIGH']} high &middot; {counts['MEDIUM']} medium &middot; {counts['LOW']} low</div>
    </div>
  </div>

  <section>
    <h2><i class="ti ti-chart-bar"></i> Severity breakdown</h2>
    <div class="chart-wrap"><canvas id="sevChart" role="img" aria-label="Bar chart of findings by severity"></canvas></div>
  </section>

  {f'''<section>
    <h2>Attack paths</h2>
    {paths_html}
  </section>''' if paths_html else ''}

  <section>
    <h2>Findings ({len(sorted_findings)})</h2>
    <div class="filter-bar">
      <button class="filter-btn active" onclick="filterFindings('all', this)">All</button>
      <button class="filter-btn" onclick="filterFindings('CRITICAL', this)">Critical</button>
      <button class="filter-btn" onclick="filterFindings('HIGH', this)">High</button>
      <button class="filter-btn" onclick="filterFindings('MEDIUM', this)">Medium</button>
      <button class="filter-btn" onclick="filterFindings('LOW', this)">Low</button>
    </div>
    <div id="findingsList">
      {findings_html}
    </div>
  </section>

  <footer>
    Generated by AgentScan &middot; <a href="https://github.com/agentscan/agentscan">github.com/agentscan/agentscan</a>
  </footer>

</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<script>
new Chart(document.getElementById('sevChart'), {{
  type: 'bar',
  data: {{
    labels: {json.dumps(chart_labels)},
    datasets: [{{ data: {json.dumps(chart_values)}, backgroundColor: {json.dumps(chart_colours)}, borderRadius: 4 }}]
  }},
  options: {{
    responsive: true, maintainAspectRatio: false,
    plugins: {{ legend: {{ display: false }} }},
    scales: {{ y: {{ beginAtZero: true, ticks: {{ stepSize: 1 }} }} }}
  }}
}});

function filterFindings(sev, btn) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.finding-card').forEach(card => {{
    const badge = card.querySelector('.sev-badge');
    const cardSev = badge ? badge.textContent.trim() : '';
    card.style.display = (sev === 'all' || cardSev === sev) ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""

    Path(output_path).write_text(html, encoding="utf-8")
    return output_path
