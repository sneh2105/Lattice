# -*- coding: utf-8 -*-
"""
Attack Graph Visualiser
========================
Renders the attack graph as:
  1. Terminal ASCII art (immediate, shareable)
  2. HTML interactive graph (D3.js force-directed, for browser)
  3. DOT format (Graphviz, for CI/CD pipelines)
"""

from __future__ import annotations
import json
from agentscan.graph.engine import AttackGraph, GraphPath
from agentscan.graph.nodes import NodeType, EdgeType


# ANSI colours
RED    = "\033[91m"
ORANGE = "\033[33m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

NODE_COLOURS = {
    NodeType.ENTRY_POINT:  RED,
    NodeType.TOOL:         CYAN,
    NodeType.RESOURCE:     YELLOW,
    NodeType.NETWORK:      ORANGE,
    NodeType.AGENT:        BLUE,
    NodeType.MCP_SERVER:   BLUE,
    NodeType.PROCESS:      RED,
    NodeType.CROWN_JEWEL:  RED,
}

NODE_ICONS = {
    NodeType.ENTRY_POINT:  "*",
    NodeType.TOOL:         "?",
    NodeType.RESOURCE:     "?",
    NodeType.NETWORK:      "?",
    NodeType.AGENT:        "?",
    NodeType.MCP_SERVER:   "?",
    NodeType.PROCESS:      "?",
    NodeType.CROWN_JEWEL:  "?",
}

EDGE_SYMBOLS = {
    EdgeType.EXECUTES:    "--exec--?",
    EdgeType.READS:       "--read--?",
    EdgeType.WRITES:      "--write-?",
    EdgeType.CALLS:       "--call--?",
    EdgeType.EXFILTRATES: "==EXFIL=?",
    EdgeType.ESCALATES:   "==ESCA==?",
    EdgeType.INJECTS:     "--inject?",
    EdgeType.DEPENDS_ON:  "--dep---?",
    EdgeType.TRUSTS:      "--trust-?",
}


def render_terminal(graph: AttackGraph, paths: list[GraphPath]) -> str:
    lines = []
    lines.append(f"\n  {BOLD}{CYAN}Attack Graph{RESET}  {DIM}({len(graph.nodes)} nodes - {len(graph.edges)} edges){RESET}\n")

    if not paths:
        lines.append(f"  {GREEN}[OK] No attack paths found from attacker-controlled entry points.{RESET}\n")
        return "\n".join(lines)

    lines.append(f"  {RED}{BOLD}[!] {len(paths)} attack path(s) found{RESET}\n")

    for i, path in enumerate(paths, 1):
        score_col = RED if path.composite_score >= 60 else ORANGE if path.composite_score >= 35 else YELLOW
        lines.append(f"  {BOLD}Path {i}: {path.title}{RESET}")
        lines.append(f"  {DIM}Exploitability: {path.exploitability:.0%}  "
                     f"Impact: {path.impact}/100  "
                     f"Score: {score_col}{path.composite_score:.1f}{RESET}")
        lines.append("")

        # Draw the chain
        for j, node in enumerate(path.nodes):
            col = NODE_COLOURS.get(node.type, "")
            icon = NODE_ICONS.get(node.type, "*")
            crown = f"  {RED}? CROWN JEWEL{RESET}" if node.is_crown_jewel else ""
            attacker = f"  {RED}? ATTACKER ENTRY{RESET}" if node.attacker_controlled else ""
            lines.append(f"  {'  ' * j}{col}{icon} {node.label}{RESET}{crown}{attacker}")

            if j < len(path.edges):
                edge = path.edges[j]
                sym = EDGE_SYMBOLS.get(edge.type, "------?")
                edge_col = RED if edge.type in (EdgeType.EXFILTRATES, EdgeType.ESCALATES, EdgeType.EXECUTES) else DIM
                lines.append(f"  {'  ' * j}  {edge_col}{sym}{RESET}")

        if path.mitre_atlas:
            lines.append(f"\n  {DIM}MITRE ATLAS: {', '.join(path.mitre_atlas)}{RESET}")
        lines.append(f"\n  {DIM}{'-' * 60}{RESET}\n")

    return "\n".join(lines)


def render_html(graph: AttackGraph, paths: list[GraphPath], title: str = "AgentScan Attack Graph") -> str:
    """Interactive D3.js force-directed graph."""
    graph_data = graph.to_dict()

    # Colour nodes for D3
    node_colors = {
        "entry_point":  "#e74c3c",
        "tool":         "#3498db",
        "resource":     "#f39c12",
        "network":      "#e67e22",
        "agent":        "#9b59b6",
        "mcp_server":   "#2980b9",
        "process":      "#c0392b",
        "crown_jewel":  "#e74c3c",
    }

    edge_colors = {
        "executes":    "#e74c3c",
        "exfiltrates": "#c0392b",
        "escalates":   "#e67e22",
        "injects":     "#e74c3c",
        "reads":       "#3498db",
        "writes":      "#f39c12",
        "calls":       "#95a5a6",
        "depends_on":  "#bdc3c7",
        "trusts":      "#2ecc71",
    }

    # Only include nodes that have edges (prune isolated nodes for clarity)
    connected = set()
    for e in graph_data["edges"]:
        connected.add(e["src"])
        connected.add(e["dst"])

    # Build path highlight data
    path_node_sets = []
    for p in paths[:5]:  # show top 5 paths
        path_node_sets.append({
            "nodes": [n.id for n in p.nodes],
            "title": p.title,
            "score": p.composite_score,
        })

    nodes_json = json.dumps([n for n in graph_data["nodes"] if n["id"] in connected])
    edges_json = json.dumps(graph_data["edges"])
    paths_json = json.dumps(path_node_sets)
    node_colors_json = json.dumps(node_colors)
    edge_colors_json = json.dumps(edge_colors)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{title}</title>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ background: #0d1117; color: #e6edf3; font-family: 'Segoe UI', system-ui, sans-serif; }}
#header {{ background: #161b22; border-bottom: 1px solid #30363d; padding: 16px 24px; display: flex; align-items: center; gap: 16px; }}
#header h1 {{ font-size: 18px; color: #58a6ff; }}
#header .badge {{ background: #da3633; color: white; padding: 2px 10px; border-radius: 12px; font-size: 12px; font-weight: 600; }}
#main {{ display: flex; height: calc(100vh - 57px); }}
#sidebar {{ width: 320px; background: #161b22; border-right: 1px solid #30363d; overflow-y: auto; padding: 16px; flex-shrink: 0; }}
#sidebar h2 {{ font-size: 13px; color: #8b949e; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 12px; }}
.path-card {{ background: #21262d; border: 1px solid #30363d; border-radius: 6px; padding: 12px; margin-bottom: 8px; cursor: pointer; transition: border-color 0.2s; }}
.path-card:hover {{ border-color: #58a6ff; }}
.path-card.active {{ border-color: #da3633; }}
.path-title {{ font-size: 12px; font-weight: 600; color: #e6edf3; margin-bottom: 4px; }}
.path-score {{ font-size: 11px; color: #8b949e; }}
.path-chain {{ font-size: 10px; color: #58a6ff; margin-top: 6px; font-family: monospace; }}
#legend {{ margin-top: 20px; }}
.legend-item {{ display: flex; align-items: center; gap: 8px; margin-bottom: 6px; font-size: 11px; color: #8b949e; }}
.legend-dot {{ width: 12px; height: 12px; border-radius: 50%; flex-shrink: 0; }}
#graph {{ flex: 1; position: relative; }}
svg {{ width: 100%; height: 100%; }}
.node circle {{ stroke-width: 2; cursor: pointer; transition: r 0.2s; }}
.node circle:hover {{ stroke-width: 3; }}
.node text {{ font-size: 11px; fill: #e6edf3; pointer-events: none; text-anchor: middle; }}
.node.crown-jewel circle {{ stroke: #f85149; stroke-width: 3; }}
.node.entry circle {{ stroke: #f85149; stroke-dasharray: 4; }}
.link {{ stroke-opacity: 0.6; marker-end: url(#arrow); }}
.link.exfiltrates, .link.executes {{ stroke-width: 2.5; stroke-opacity: 0.9; }}
.link-label {{ font-size: 9px; fill: #8b949e; }}
#tooltip {{ position: absolute; background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 10px 14px; font-size: 12px; pointer-events: none; opacity: 0; transition: opacity 0.15s; max-width: 250px; z-index: 100; }}
.highlight-path {{ stroke: #f85149 !important; stroke-width: 3 !important; stroke-opacity: 1 !important; }}
.highlight-node circle {{ stroke: #f85149 !important; stroke-width: 3 !important; r: 14 !important; }}
</style>
</head>
<body>
<div id="header">
  <h1>?? AgentScan -- Attack Graph</h1>
  <span class="badge">{len(paths)} critical path(s)</span>
  <span style="color:#8b949e;font-size:13px;margin-left:auto">{len(graph_data['nodes'])} nodes - {len(graph_data['edges'])} edges</span>
</div>
<div id="main">
  <div id="sidebar">
    <h2>Attack Paths</h2>
    <div id="path-list"></div>
    <div id="legend">
      <h2 style="margin-bottom:10px">Legend</h2>
      <div class="legend-item"><div class="legend-dot" style="background:#e74c3c"></div>Entry Point / Crown Jewel</div>
      <div class="legend-item"><div class="legend-dot" style="background:#9b59b6"></div>Agent / MCP Server</div>
      <div class="legend-item"><div class="legend-dot" style="background:#3498db"></div>Tool</div>
      <div class="legend-item"><div class="legend-dot" style="background:#f39c12"></div>Resource / Data</div>
      <div class="legend-item"><div class="legend-dot" style="background:#e67e22"></div>External Network</div>
    </div>
  </div>
  <div id="graph">
    <div id="tooltip"></div>
  </div>
</div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"></script>
<script>
const nodesData = {nodes_json};
const edgesData = {edges_json};
const pathsData = {paths_json};
const nodeColors = {node_colors_json};
const edgeColors = {edge_colors_json};

const width = document.getElementById('graph').clientWidth;
const height = document.getElementById('graph').clientHeight;

const svg = d3.select('#graph').append('svg');
const g = svg.append('g');

// Zoom
svg.call(d3.zoom().scaleExtent([0.3, 3]).on('zoom', e => g.attr('transform', e.transform)));

// Arrow markers
const defs = svg.append('defs');
['default','red','orange'].forEach((col, i) => {{
  defs.append('marker').attr('id', `arrow-${{col}}`).attr('viewBox','0 -4 10 8')
    .attr('refX', 22).attr('refY', 0).attr('markerWidth', 6).attr('markerHeight', 6)
    .attr('orient', 'auto')
    .append('path').attr('d', 'M0,-4L10,0L0,4').attr('fill',
      col === 'red' ? '#f85149' : col === 'orange' ? '#e67e22' : '#8b949e');
}});

// Build node map
const nodeById = {{}};
nodesData.forEach(n => nodeById[n.id] = n);

// Simulation
const sim = d3.forceSimulation(nodesData)
  .force('link', d3.forceLink(edgesData).id(d => d.id).distance(120))
  .force('charge', d3.forceManyBody().strength(-400))
  .force('center', d3.forceCenter(width/2, height/2))
  .force('collision', d3.forceCollide(30));

// Links
const link = g.selectAll('.link').data(edgesData).enter().append('line')
  .attr('class', d => `link ${{d.type}}`)
  .style('stroke', d => edgeColors[d.type] || '#8b949e')
  .style('stroke-width', d => ['exfiltrates','executes','escalates'].includes(d.type) ? 2.5 : 1.5)
  .attr('marker-end', d => ['exfiltrates','executes','escalates','injects'].includes(d.type)
    ? 'url(#arrow-red)' : 'url(#arrow-default)');

// Nodes
const node = g.selectAll('.node').data(nodesData).enter().append('g')
  .attr('class', d => `node ${{d.is_crown_jewel ? 'crown-jewel' : ''}} ${{d.attacker_controlled ? 'entry' : ''}}`)
  .call(d3.drag().on('start', (e,d) => {{ if(!e.active) sim.alphaTarget(0.3).restart(); d.fx=d.x; d.fy=d.y; }})
    .on('drag', (e,d) => {{ d.fx=e.x; d.fy=e.y; }})
    .on('end', (e,d) => {{ if(!e.active) sim.alphaTarget(0); d.fx=null; d.fy=null; }}));

node.append('circle')
  .attr('r', d => d.is_crown_jewel || d.attacker_controlled ? 14 : d.type === 'agent' || d.type === 'mcp_server' ? 13 : 10)
  .style('fill', d => nodeColors[d.type] || '#666')
  .style('stroke', d => d.is_crown_jewel ? '#f85149' : d.attacker_controlled ? '#f85149' : '#30363d');

node.append('text').attr('dy', 24).text(d => d.label.length > 20 ? d.label.slice(0,18)+'...' : d.label);

// Tooltip
const tooltip = document.getElementById('tooltip');
node.on('mouseover', (e, d) => {{
  tooltip.style.opacity = '1';
  tooltip.style.left = (e.offsetX + 15) + 'px';
  tooltip.style.top = (e.offsetY - 10) + 'px';
  tooltip.innerHTML = `<b style="color:#58a6ff">${{d.label}}</b><br>
    <span style="color:#8b949e">Type: ${{d.type}}</span><br>
    ${{d.is_crown_jewel ? `<span style="color:#f85149">? Crown Jewel (value: ${{d.crown_jewel_value}})</span><br>` : ''}}
    ${{d.attacker_controlled ? '<span style="color:#f85149">* Attacker-controlled</span><br>' : ''}}
    ${{d.properties?.impact ? `Impact: ${{d.properties.impact}}` : ''}}`;
}}).on('mouseout', () => {{ tooltip.style.opacity = '0'; }});

sim.on('tick', () => {{
  link.attr('x1', d => d.source.x).attr('y1', d => d.source.y)
      .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
  node.attr('transform', d => `translate(${{d.x}},${{d.y}})`);
}});

// Sidebar paths
let activePathIdx = -1;
const pathList = document.getElementById('path-list');
pathsData.forEach((p, i) => {{
  const card = document.createElement('div');
  card.className = 'path-card';
  card.innerHTML = `<div class="path-title">${{p.title}}</div>
    <div class="path-score">Score: ${{p.score.toFixed(1)}}</div>
    <div class="path-chain">${{p.nodes.join(' -> ')}}</div>`;
  card.onclick = () => {{
    document.querySelectorAll('.path-card').forEach(c => c.classList.remove('active'));
    card.classList.add('active');
    // Highlight path nodes and edges
    const pathNodeSet = new Set(p.nodes);
    node.classed('highlight-node', d => pathNodeSet.has(d.id));
    link.classed('highlight-path', d => pathNodeSet.has(d.source.id) && pathNodeSet.has(d.target.id));
  }};
  pathList.appendChild(card);
}});
</script>
</body>
</html>"""
