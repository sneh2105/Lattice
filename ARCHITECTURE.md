# Architecture Overview

How Lattice is put together, and why. Written for someone deciding whether
to contribute, extend, or just trust the tool.

---

## The core principle: one canonical scan, many consumers

Early versions of this codebase had a real, recurring bug class: the CLI's
PDF export, the dashboard's Compliance tab, and the Attack Graph each built
their own version of a scan result independently. They drifted. A finding
accepted as a risk would show correctly in one place and silently vanish
from another. A merged source+MCP scan would show 6 findings in the
Findings tab and 2 in the PDF, because the PDF re-ran only the source
scanner.

The fix, and the architectural rule going forward:

> **Every consumer that needs scan data calls the same canonical function.
> No consumer re-derives its own version of "what did we find."**

Concretely: `agentscan/ui_server.py::_build_merged_result()` is the single
entry point. It handles GitHub URLs, local directories (merging source +
any discovered MCP manifests), single files, and live MCP endpoints, and
returns one `ScanResult`. Compliance, PDF export, SARIF export, the Attack
Graph, and the dashboard's Summary/Findings tabs all call this function --
never a scanner directly. If you're adding a new report or view, this is
the function you call.

The same principle applies one level down: `agentscan/risk_register.py::filter_by_disposition()`
is the single function that decides "what still counts as open risk" after
a user has accepted, disputed, or remediated findings. Compliance scoring,
DPIA generation, and the Control Mapping table all call this -- not their
own copy of the same logic.

---

## Pipeline

```
Input (file / directory / GitHub URL / MCP endpoint)
        |
        v
_build_merged_result()  <-- THE canonical entry point
        |
        +--> source_scanner.py   (AST walk of Python files)
        +--> agent_scanner.py    (YAML/JSON declarative configs)
        +--> mcp_scanner.py      (MCP manifests / live servers)
        |
        v
   ScanResult
     .findings        -- list[Finding]
     .attack_paths     -- list[AttackPath]  (built by combining capabilities)
     .metadata         -- capabilities_detected, cap_to_tools, dependency_files, etc.
        |
        +--> risk_register.annotate_finding_objects()  -- attaches .status to each Finding
        |
        v
   ================================================================
   ||  Consumers (all read the SAME annotated ScanResult)          ||
   ================================================================
        |
        +--> outputs/terminal.py       (CLI text output)
        +--> outputs/json_output.py    (JSON, SARIF 2.1.0)
        +--> outputs/html_report.py    (standalone HTML report)
        +--> graph/engine.py           (build_graph_from_scan -> AttackGraph)
        +--> compliance/framework_mapper.py  (map_findings_to_controls -> ComplianceReport)
        +--> compliance/dpia.py        (generate_dpia -> DPIADocument)
        +--> compliance/audit_report.py (generate_audit_report -> PDF)
        +--> ui_server.py / dashboard.html  (local Flask app + single-page UI)
```

---

## Key modules

```
agentscan/
├── _compat.py              Windows compatibility: forces UTF-8 stdout/stderr,
│                            ASCII symbol fallbacks for cp1252 terminals
├── _fileutil.py             Atomic file writes, path validators
├── cli.py                   argparse-based CLI entry point, all subcommands
├── models.py                Finding, AttackPath, ScanResult, Severity, ConfidenceLevel
├── risk_register.py         4-state finding disposition (open/accepted_risk/
│                            false_positive/remediated), raw vs governed scoring,
│                            filter_by_disposition() -- the shared "what's still
│                            open" function
├── drift.py                 Fingerprint-based diff between two scans (baseline
│                            capture + compare, used by `agentscan diff`)
│
├── scanners/
│   ├── capabilities.py       CANONICAL capability taxonomy -- every scanner
│   │                         imports from here, never duplicates keyword lists
│   ├── source_scanner.py     Python AST scanner: decorators, BaseTool subclasses
│   │                         (including wrapper-class inheritance), raw schemas,
│   │                         AST-body behavioral detection (eval/exec/subprocess)
│   ├── agent_scanner.py      YAML/JSON scanner: standard configs, Dify, n8n,
│   │                         Flowise, capability-combination attack path builder
│   ├── mcp_scanner.py        MCP manifest/live server scanner
│   └── supply_chain_scanner.py  PyPI/npm/HuggingFace/dataset scanner
│
├── graph/
│   ├── nodes.py              Node/Edge/NodeType/EdgeType definitions
│   ├── engine.py             build_graph_from_scan() -- builds directly from
│   │                         ScanResult.attack_paths, NOT from a separately
│   │                         reconstructed capability graph (see "Attack Graph"
│   │                         section below)
│   └── cli_graph.py          `agentscan graph` command + terminal renderer
│
├── compliance/
│   ├── framework_mapper.py   Finding -> control mapping across RBI/DPDP/ISO
│   │                         42001/EU AI Act/NIST AI RMF/SOC 2/SEBI CSCRF
│   ├── dpia.py                Data Protection Impact Assessment generator
│   └── audit_report.py       PDF generation (ReportLab) -- cover page,
│                              executive summary, findings table, control
│                              mapping, risk acceptance register
│
├── outputs/
│   ├── terminal.py           Colored CLI text output
│   ├── json_output.py        JSON + SARIF 2.1.0
│   └── html_report.py        Standalone HTML report (D3.js + Chart.js embedded
│                              inline -- works fully offline, no CDN)
│
├── ui_server.py               Flask backend for the dashboard. Owns
│                              _build_merged_result() (see above), all
│                              /api/* routes
├── dashboard.html              The dashboard itself -- single HTML file,
│                                vanilla JS (no build step), D3 embedded inline
│
└── runtime/                   Runtime monitoring SDK (separate, less mature
                                subsystem -- see "What's runtime/ for?" below)
```

---

## Why AST-based static analysis, not an LLM-based scanner

An obvious alternative design would be "ask an LLM to read the code and
tell you if it's dangerous." We didn't build it that way, for reasons that
matter if you're evaluating this for a security program:

- **Determinism.** The same input must always produce the same output. An
  LLM-based scanner can't guarantee that, which breaks CI/CD gating
  (`--fail-on HIGH` needs to mean the same thing on every run) and breaks
  drift detection (comparing two scans requires stable, reproducible
  findings).
- **No API key, no cost, no data leaving the machine.** A scanner that
  requires sending your source code to a third-party LLM API is a
  non-starter for a lot of security teams, and adds a real per-scan cost.
- **Auditability.** Every finding traces back to a specific AST node, tag,
  and capability-combination rule you can read in `capabilities.py`. You
  can point to the exact line of Python that decided a finding fired. An
  LLM's reasoning is not inspectable the same way.

The tradeoff is real: an LLM might catch a genuinely novel obfuscation
pattern that a fixed rule set misses. We accept that tradeoff in exchange
for the properties above, and mitigate it with the AST-body behavioral
detection layer (which catches many of the "renamed to look innocent"
cases without needing an LLM).

---

## Attack Graph: built from `attack_paths`, not re-derived

This deserves its own note because it was the source of a real, subtle bug
that took several rounds to fully fix.

**Wrong approach (what an earlier version did):** build the graph
independently from `ScanResult.metadata["capabilities_detected"]`, using a
separate BFS pathfinding pass to discover paths. This produces a graph that
*looks* related to the scan results but is a completely separate
computation -- it can show different path counts, different names, and
can silently omit findings that don't fit its capability-map assumptions
(this is exactly what happened to AST-behavioral findings like `eval()`
detection, which had no entry in the older capability-to-edge map).

**Current approach:** `build_graph_from_scan()` walks `ScanResult.attack_paths`
directly -- the exact same list the PDF, compliance report, and JSON/SARIF
output read from -- and constructs one `GraphPath` per `AttackPath`. A
`_node_spec_for_finding()` lookup maps each finding's tags to a specific
node type and label (with `code_execution` vs `shell_exec` deliberately
kept as distinct node types, since eval()-based code execution and
subprocess-based shell execution are different exploitation mechanisms
with different remediation).

A standalone CRITICAL/HIGH finding that never combined into a multi-tool
`AttackPath` (e.g. a lone `eval()` finding with no paired capability) still
gets its own graph node and path -- it does not silently disappear just
because no chain formed. See `graph/engine.py` for the exact logic.

---

## The dashboard: local-only, no build step

`agentscan ui` starts a Flask app bound to `localhost` on a random free
port, and opens your default browser to it. There is no separate frontend
build (no webpack, no npm install) -- `dashboard.html` is one file with
inline `<style>` and `<script>` tags, D3.js and Chart.js embedded directly
in the HTML (not loaded from a CDN, so it works fully offline and isn't
blocked by browsers refusing external scripts on `file://` pages).

The server process exits when you close the terminal or press Ctrl+C.
Nothing persists server-side between runs except the risk acceptance
register (`~/.agentscan/risk_register.json`) and saved drift baselines
(`~/.agentscan/baselines/`) -- both plain JSON, both readable by hand.

---

## What's `runtime/` for?

A separate, intentionally less mature subsystem: hooks for LangChain,
CrewAI, AutoGen, and OpenAI-based agents that let you monitor an agent's
*actual* tool calls during a live session, rather than statically analyzing
its code. This answers a different question ("what did this agent actually
do in this conversation?") from the rest of the tool ("what could this
agent's code do in theory?"). It's CLI-only (`agentscan runtime analyse`)
and not yet wired into the dashboard -- treat it as an early-stage
companion feature, not a fully supported product surface.

---

## Test architecture

274 tests, all in `tests/unit/`. A few patterns worth knowing:

- **Fixture isolation for stateful modules:** `risk_register.py` and
  `drift.py` write to files under `~/.agentscan/`. Tests use `monkeypatch`
  to redirect these paths to a temp directory per test, so tests never
  pollute the real user's risk register or each other.
- **Real fixtures over mocks where it matters:** most detection tests build
  a real temp Python file and run the actual `scan_source()` against it,
  rather than mocking the AST scanner. This is slower but catches real
  regressions that a mocked test would miss (several of the bugs fixed in
  this project's history were only caught this way).
- **Subprocess tests always pass `encoding="utf-8"`:** any test that shells
  out to the `agentscan` CLI must set this explicitly, or it silently uses
  the platform default encoding and breaks on Windows.
