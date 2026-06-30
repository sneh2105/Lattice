<div align="center">

# 🛡️ AgentScan

**Security scanner for AI agents, MCP servers, and AI supply chain artifacts**

*Attack Graph Engine · MCP Trust Scoring · Compliance Reporting (RBI · DPDP · ISO 42001 · EU AI Act · SOC 2)*

[![CI](https://github.com/agentscan/agentscan/actions/workflows/ci.yml/badge.svg)](https://github.com/agentscan/agentscan/actions)
[![PyPI](https://img.shields.io/pypi/v/agentscan)](https://pypi.org/project/agentscan/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-32%20passing-brightgreen)](tests/)

</div>

---

## What is AgentScan?

AgentScan is an open-source security scanner that analyses AI agents, MCP servers, and AI supply chain artifacts. It builds a real **attack graph** — showing complete chains from attacker-controlled inputs to high-value targets — and maps findings to compliance controls across 8 frameworks.

```
User Prompt  ──inject──▶  Agent  ──call──▶  shell_exec  ══exec══▶  OS Shell  👑
                                  ──call──▶  aws_secrets ══EXFIL═▶  External Network
                                  ──call──▶  db_query    ──read──▶  PII Data Store  👑

Blast radius from user_prompt: 6 crown jewels reachable  Aggregate impact: 100/100
```

---

## Quick start

```bash
pip install agentscan

# Scan agent configs
agentscan agent  my_agent.yaml
agentscan mcp    mcp_server.json
agentscan supply pypi:langchain
agentscan supply hf:microsoft/phi-3

# Attack graph
agentscan graph agent my_agent.yaml
agentscan graph mcp   mcp_server.json
agentscan graph agent my_agent.yaml --export-html graph.html   # interactive D3.js

# Compliance
agentscan compliance map   my_agent.yaml           # RBI · DPDP · ISO 42001 · EU AI Act
agentscan compliance dpia  my_agent.yaml           # Data Protection Impact Assessment
agentscan compliance audit my_agent.yaml \         # Board-level PDF audit report
  --organisation "Acme Bank" --output-file audit.pdf

# CI/CD
agentscan agent my_agent.yaml --output sarif --output-file results.sarif
agentscan agent my_agent.yaml --fail-on HIGH
```

---

## Architecture

```
agentscan/
├── scanners/
│   ├── agent_scanner.py        Parses agent configs — tools, capabilities, system prompt
│   ├── mcp_scanner.py          MCP manifest / live server analysis (v1, fast)
│   ├── mcp_scanner_v2.py       Full MCP platform — trust score + risk score + graph
│   └── supply_chain_scanner.py HuggingFace models + PyPI packages
│
├── graph/
│   ├── nodes.py                Node/Edge types — TOOL, RESOURCE, CROWN_JEWEL, ENTRY_POINT…
│   ├── engine.py               BFS reachability, path finding, blast radius, trust scoring
│   ├── visualiser.py           Terminal ASCII · interactive D3.js HTML · DOT/Graphviz
│   └── cli_graph.py            agentscan graph agent / mcp commands
│
├── compliance/
│   ├── framework_mapper.py     Finding → control mapping (RBI · DPDP · SEBI · ISO 42001 · EU AI Act · NIST · SOC 2)
│   ├── dpia.py                 DPIA generator (6 sections, DPDP/ISO 42001/EU AI Act)
│   └── audit_report.py        PDF audit report (board sign-off, CERT-In, ISO auditor)
│
├── outputs/
│   ├── terminal.py             Coloured CLI output with risk bar, attack chains
│   └── json_output.py         JSON + SARIF 2.1.0 (GitHub Security tab)
│
└── models.py                   Finding · AttackPath · Evidence · ScanResult
```

---

## Attack Graph Engine

Every scan builds a directed graph:

| Node type | Examples |
|---|---|
| `ENTRY_POINT` | User prompt, tool response, RAG context |
| `TOOL` | shell_exec, db_query, http_fetch |
| `AGENT` / `MCP_SERVER` | The agent or server being scanned |
| `RESOURCE` | Filesystem, database |
| `CROWN_JEWEL` | AWS credentials (100), shell access (95), PII (85), DB (85) |
| `NETWORK` | External internet (60) |

The engine runs BFS reachability from every attacker-controlled entry point. Paths are scored by `exploitability × impact` and ranked. Blast radius shows how many crown jewels are reachable and the aggregate impact.

```bash
agentscan graph agent agent.yaml

# Output:
# ⚠ 6 attack path(s) found
#
# Path 1: User Prompt → OS Shell / Command Execution
#   Exploitability: 77%  Impact: 95/100  Score: 73.4
#   ⚡ User Prompt  ← ATTACKER ENTRY
#     ──inject──▶
#     🤖 Agent
#       ──call──▶
#       🔧 shell_exec
#         ══exec══▶
#         💻 OS Shell  ← CROWN JEWEL
#
# Blast Radius from user_prompt:
#   Crown jewels reachable: Shell, AWS Creds, API Keys, DB, PII, Network
#   Aggregate impact: 100/100
```

Export as interactive D3.js graph (`--export-html graph.html`) — click paths to highlight them, hover nodes for details, drag to rearrange.

---

## MCP Security Platform

Two distinct scores for each MCP server:

- **Trust score (0–100)** — how much should you trust this server as a source?
  Deductions: no auth (−20), wildcard permissions (−15), unknown publisher (−10), reachable from attacker entry (−15), dangerous tools (up to −40)

- **Risk score (0–100)** — how dangerous are its capabilities?
  shell_exec (+40), code_execution (+40), secret_access (+35), cloud_api (+30)…

```bash
agentscan graph mcp dangerous_server.json

# MCP Security Platform — dev-tools-server
# Trust score   25/100  █████░░░░░░░░░░░░░░░  [LOW]
# Risk score   100/100  ████████████████████
#
# Trust deductions:
#   No authentication configured
#   Publisher 'unknown' not in trusted registry
#   High-risk tools: run_shell_command, get_aws_secret
#
# Tool analysis:
#   ● run_shell_command  [CRITICAL]  shell_exec
#   ● http_request       [MEDIUM]    network_egress
#   ● get_aws_secret     [CRITICAL]  secret_access, cloud_api
```

---

## Compliance Coverage

Every finding maps to specific controls across 8 frameworks:

| Framework | Controls mapped | Key requirement |
|---|---|---|
| **RBI AI-ACT&RS** | AIACTS-2.1, 3.1, 3.2, 4.1 | AI risk assessment, credential protection, supply chain |
| **RBI MRM 2026** | MRM-3.2, 4.1, 4.3 | Guardrails, autonomy boundaries, board sign-off |
| **DPDP Act 2023** | DPDP-R3, R6, R8, R9 | Security safeguards, data flows, breach notification |
| **SEBI CSCRF** | SEBI-CSCRF-3.1, 4.2, 5.1 | Vendor risk, DLP, third-party AI software |
| **ISO 42001** | 8.3, 8.4, 8.5, 8.6, 8.7 | AI operational controls, supply chain, DPIA |
| **EU AI Act** | Art. 9, 10, 14, 16, 25 | Risk management, human oversight, deployer obligations |
| **NIST AI RMF** | MAP-5.1, MANAGE-2.4 | Supply chain transparency, risk treatment |
| **SOC 2** | CC6.1, 6.3, 6.6, 6.8, 7.2, 9.2 | Access controls, network boundary, vendor risk |

### Compliance commands

```bash
# See exact controls your agent violates
agentscan compliance map ./agent.yaml

# Generate DPIA (6 sections: description, necessity, risks, data flows, controls, recommendation)
agentscan compliance dpia ./agent.yaml --agent-name "Support Bot" --output-file dpia.json

# Generate PDF audit report (board sign-off page, findings table, control mapping, DPIA)
agentscan compliance audit ./agent.yaml \
  --organisation "Acme Bank" \
  --agent-name "Support Bot" \
  --output-file audit.pdf
```

The PDF includes: cover page, executive summary (risk score, posture, attack path count), attack paths, findings table, compliance control mapping table, DPDP manual review gaps, full DPIA, and sign-off page for CISO / DPO / Board Rep / Compliance Officer.

---

## Output formats

| Format | Use |
|---|---|
| `text` (default) | Coloured terminal output with risk bar, attack chains, evidence |
| `json` | Machine-readable, all findings + attack paths + metadata |
| `sarif` | GitHub Security tab, VS Code, any SARIF-compatible tool |
| HTML graph | Interactive D3.js attack graph (`--export-html`) |
| PDF | Board-level compliance audit report |

---

## CI/CD integration

**GitHub Actions + SARIF:**
```yaml
- name: AgentScan
  run: |
    pip install agentscan
    agentscan agent agent.yaml --output sarif --output-file results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

**Fail CI on HIGH findings:**
```bash
agentscan agent agent.yaml --fail-on HIGH
```

**pre-commit hook:**
```yaml
repos:
  - repo: local
    hooks:
      - id: agentscan
        name: AgentScan
        entry: agentscan agent
        language: python
        files: \.(yaml|yml|json)$
```

---

## What every finding includes

Every finding — no exceptions — carries:
- Severity (CRITICAL / HIGH / MEDIUM / LOW) + Confidence (HIGH / MEDIUM)
- Plain-English explanation of what is happening
- Impact statement (what an attacker can do)
- Evidence (exact source, field, observed value, reason it triggered)
- Concrete remediation step
- MITRE ATLAS technique mapping
- CWE mapping where applicable
- Compliance controls implicated (via `compliance map`)

Low-confidence findings are suppressed by default. Innocuous tools (calculator, weather, jokes) produce zero CRITICAL/HIGH findings.

---

## Supported inputs

| Target | Format |
|---|---|
| Agent configs | YAML, JSON (LangChain, AutoGen, CrewAI, OpenAI Assistants, custom) |
| MCP servers | Manifest (JSON/YAML) or live HTTP(S) server |
| HuggingFace models | `hf:<org>/<model>` |
| PyPI packages | `pypi:<name>` |
| npm packages | `npm:<name>` *(v0.3 — coming soon)* |

---

## Roadmap

- [ ] Runtime agent monitoring SDK / sidecar
- [ ] npm supply chain scanning
- [ ] Dataset poisoning detection (HuggingFace datasets)
- [ ] Multi-server MCP trust chain analysis
- [ ] Cross-scanner attack paths (supply chain → agent graph)
- [ ] Web UI (paste config, get report)
- [ ] VS Code extension
- [ ] Jira / webhook integration
- [ ] Fleet scanning (all agents in an org)

---

## Contributing

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

Priority areas: agent config format parsers (AutoGen, LangGraph), npm scanner, additional MITRE ATLAS technique mappings, integration tests against real MCP servers.

---

## License

Apache 2.0 — free for commercial use.

<div align="center">
Built for the AI security community.
<br>
<a href="https://github.com/agentscan/agentscan/issues">Report issues</a> ·
<a href="https://github.com/agentscan/agentscan/discussions">Discuss</a>
</div>
