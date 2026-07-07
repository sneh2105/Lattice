# Changelog

## v0.4.2 (2026-07-07)

### Fixed
- **Attack Graph missing standalone CRITICAL findings** — a lone behavioral
  finding (e.g. `calculator`'s `eval()`-based code-execution detection) that
  never combined with another capability into a multi-tool attack chain was
  completely absent from the Attack Graph, even though it appeared in every
  PDF/JSON/Findings output. It now renders as its own standalone path
  connected from the agent.
- **Duplicated hop in multi-capability tool paths** — when one tool carries
  two capability findings (e.g. an AWS client tagged both `secret_access`
  and `cloud_api`), the path renderer was re-adding the "agent invokes tool"
  edge and re-chaining through the tool a second time, producing a
  nonsensical `tool -> tool` self-loop (visible as e.g.
  `tool_aws_secrets_manager -> aws_credentials -> tool_aws_secrets_manager ->
  aws_credentials`). Fixed: one tool node now carries both outbound
  capability edges directly, no repeated hop.
- Added regression tests for both: `test_no_duplicated_hop_when_one_tool_has_multiple_capabilities`,
  `test_standalone_critical_finding_appears_as_graph_path`.

## v0.4.1 (2026-07-07)

### Fixed — root cause of Attack Graph / PDF divergence
- `build_graph_from_scan()` previously reconstructed the graph independently
  from `metadata["capabilities_detected"]` rather than reading
  `result.attack_paths` (the same list PDF/Compliance/JSON/SARIF use). This
  is why graph path count, path names, and node content never matched the
  written report, and didn't improve across version bumps that fixed
  everything else. Rewrote to build directly from `result.attack_paths`.
- Added `graph_paths_from_attack_paths()`: converts each `AttackPath` into
  exactly one `GraphPath`, bypassing the old BFS reconstruction that deduped
  multiple paths sharing a crown jewel (under-counting relative to the PDF).
- **Orphan/disconnected nodes eliminated** — the graph previously
  pre-populated every possible entry-point and crown-jewel node regardless
  of use ("AWS / Cloud", "Tool Response" would appear floating with zero
  edges). `build_graph_from_scan` now only adds nodes an actual attack path
  touches, then prunes anything left disconnected.
- **`eval()`/`exec()` now renders as a distinct node** — "Code Execution
  (Arbitrary Python)" — separate from generic "OS Shell / Command
  Execution", since the exploitation mechanism and remediation differ.
- **MCP-derived paths recognized** — the raw MCP tag vocabulary
  (`MCP-SHELL`, `MCP-DATABASE`, `MCP-NET`, ...) is now aliased onto the
  standard capability tags the graph node-mapper understands, so MCP
  findings inside a merged attack path are mapped correctly instead of
  silently producing zero graph nodes.

## v0.4.0 (2026-07-06)

### Fixed
- **Compliance/DPIA/PDF export missing MCP findings** — for directory
  targets, Compliance/PDF/SARIF were independently re-running only
  `scan_source()`, dropping any MCP manifest findings that the
  Findings/Summary tabs already merged in. Added one canonical
  `_build_merged_result()` function; every consumer (Summary, Findings,
  Compliance, PDF, SARIF, Graph) now calls it, so they can no longer diverge.
- DPIA tool/capability count showing "0" despite non-zero findings.

### New
- **Drift detection** (`agentscan/drift.py`) — fingerprint-based comparison
  between two scans (id + tags, resilient to re-worded titles). Classifies
  into new / resolved / escalated / de-escalated / unchanged. Baseline
  capture + compare via dashboard Export tab.
- **Risk acceptance workflow** (`agentscan/risk_register.py`) — persistent
  JSON-file register recording who accepted a finding, when, and why.
  Accepted findings stay visible with a badge (never silently hidden) —
  expiry dates supported, reverts to open automatically once expired.
- Confirmed (code review): HuggingFace supply-chain scanner is implemented
  correctly. `hf:microsoft/phi-3` fails because that exact model ID does
  not exist on HuggingFace (case-sensitive; real ID is
  `Phi-3-mini-4k-instruct`) — not a scanner bug. Error message now suggests
  the correct ID for common model name typos.
- Confirmed manifest-aware batch dependency scanning was already fully
  wired end-to-end: opening the Supply Chain tab auto-reads
  `requirements.txt` / `package.json` / `pyproject.toml` directly from the
  scanned folder server-side — no paste required.

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
