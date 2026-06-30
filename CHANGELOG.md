# Changelog

## v0.2.0 (2026-06-29)

### New
- **Attack Graph Engine** (`agentscan/graph/`) — real directed graph with BFS reachability,
  DFS path finding, blast radius scoring, trust score per node
- **`agentscan graph agent`** — builds and displays attack graph from agent config
- **`agentscan graph mcp`** — full MCP trust + risk + graph analysis
- **`--export-html`** — interactive D3.js force-directed graph in browser
- **MCP Security Platform v2** (`mcp_scanner_v2.py`) — trust score (0–100) distinct from
  risk score, per-tool analysis, publisher verification, live server introspection
- **Graph node taxonomy** — ENTRY_POINT, TOOL, RESOURCE, NETWORK, AGENT, MCP_SERVER,
  PROCESS, CROWN_JEWEL with impact values
- **15 new unit tests** — graph engine (8) + MCP v2 (7)

### Improved
- Attack paths now use real graph traversal (BFS) not pattern matching
- Composite scoring: exploitability × impact, ranked highest-first
- MCP analysis now separates trust (source) from risk (capability)

## v0.1.0 (2026-06-28)

### New
- `agentscan agent` — agent config scanner (YAML/JSON)
- `agentscan mcp` — MCP manifest / live server scanner
- `agentscan supply` — HuggingFace + PyPI supply chain scanner
- `agentscan compliance map` — 8-framework control mapping
- `agentscan compliance dpia` — DPIA generator
- `agentscan compliance audit` — PDF audit report
- JSON + SARIF 2.1.0 output formats
- GitHub Actions CI + PR scanning workflows
- 17 unit tests, all passing
- Apache 2.0 licence
