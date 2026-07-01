<div align="center">

# 🛡️ AgentScan

**Find the attack path before an attacker does.**

A security scanner for AI agents and MCP servers that doesn't just list permissions —
it shows you the complete chain from a malicious prompt to a stolen credential.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-140%20passing-brightgreen)](tests/)

</div>

---

## Supported frameworks

✅ LangChain · ✅ LangGraph · ✅ CrewAI · ✅ AutoGen · ✅ OpenAI Agents SDK ·
✅ Google ADK · ✅ Semantic Kernel · ✅ Amazon Bedrock Agents · ✅ Amazon Nova Act ·
✅ MCP · ✅ No framework at all (raw Anthropic/OpenAI tool schemas) ·
✅ No-code platform exports (Dify-style)

Source code scanning (`agentscan source`) covers all of the above via AST analysis.
Declarative config scanning (`agentscan agent`) covers YAML/JSON agent configs and
no-code visual builder exports. MCP servers are scanned directly via `agentscan mcp`,
live or from a manifest.

**Not yet covered**: AI gateway configuration (Bifrost, TrueFoundry, Cloudflare AI
Gateway) — these route/observe traffic but don't define agent tools themselves, so
the application code on either side of the gateway is what AgentScan scans; the
gateway's own governance config (virtual keys, routing rules) isn't parsed yet. See
[`docs/ADVANCED.md`](docs/ADVANCED.md) for details.

## Try it with zero setup

No agent of your own handy? Run AgentScan against seven bundled, intentionally
vulnerable agents — no cloning, no config, just installed and run:

```bash
pip install -e .
agentscan demo
```

```
  Prompt injection -> shell
  An agent with browser + shell tools — a malicious web page can hijack it into running commands
  ✓ Risk 56/100  ·  1 attack path(s) found
    Remote code execution + exfiltration path
  ...
  Safe scoped search agent
  ✓ Risk 0/100  ·  0 finding(s) — no false positives

  ✓ AgentScan correctly identified all 11 attack patterns with zero false positives.
```

`agentscan benchmark` runs the same suite in a compact pass/fail table — see
[`examples/vulnerable_agents/`](examples/vulnerable_agents/) for the full
evaluation kit, including what each scenario tests and why.

## The problem

Every AI agent framework lets you bolt on tools — shell access, database queries, web browsing,
secret retrieval. Each tool looks fine in isolation. Nobody checks what happens when an agent
has three or four of them *at once*, and a prompt injection chains them together.

```yaml
tools:
  - name: aws_secrets_manager   # "we need this for deployment automation"
  - name: web_browser           # "we need this for research"
```

Individually, reasonable. Together: a complete credential exfiltration path that a single
malicious prompt can trigger.

## What AgentScan does

Real agents live in real code — LangChain, CrewAI, AutoGen — not in YAML files.
AgentScan reads that code directly, with zero execution:

```bash
pip install -e .
agentscan source ./src/agents/   # scans an entire repo for tool definitions
```

<p align="center">
  <img src=".github/assets/demo.png" alt="AgentScan terminal output showing a critical attack path found in real LangChain code" width="800">
</p>

It parses `@tool` decorators, `BaseTool` subclasses, and `register_function()` calls
across LangChain, CrewAI, and AutoGen patterns via Python's AST — no agent execution,
no API key required, works on a clone of your repo.

If you'd rather describe an agent declaratively (e.g. for a deploy-time gate, or an
agent that genuinely is config-driven), `agentscan agent` accepts YAML/JSON directly:

```
  AgentScan ──────────────────────────────────────────
  Risk score  100/100  ████████████████████

  Findings: 2 CRITICAL  3 HIGH  5 MEDIUM
  Attack paths: 4 critical chain(s) found

  ╔══ ATTACK PATHS ══════════════════════════════════════════╗
  ║  1. Credential exfiltration path
  ║     Entry : Prompt injection via user input or malicious tool output
  ║     Impact: AWS/cloud credentials, API keys exfiltrated to attacker
  ║     Chain : web_browser → aws_secrets_manager
  ║     ATLAS : AML.T0051, AML.T0040
  ╚═══════════════════════════════════════════════════════════╝

  [✗ CRITICAL] Tool 'aws_secrets_manager' grants secret access
               [confidence: HIGH]

  What's happening:
    The tool 'aws_secrets_manager' maps to the 'secret_access' capability.
    In combination with network tools, this forms a complete attack chain.

  Fix:
    Review whether this tool is required. Scope its permissions as narrowly
    as possible. Consider running the agent in a sandboxed environment.

  MITRE ATLAS: AML.T0051
```

No false-positive noise on harmless tools (calculator, weather lookup, search) — tested and
verified zero CRITICAL/HIGH findings on innocuous capabilities. Every finding ships with
the exact evidence that triggered it and a concrete fix, mapped to MITRE ATLAS.

## MCP server scanning

```bash
agentscan mcp your_mcp_manifest.json
agentscan mcp https://your-mcp-server.com   # scans a live server
```

Same attack-path detection, applied to MCP tool definitions — catches servers that combine
shell execution, credential access, and network egress into a single exploit chain.

## CI/CD integration

AgentScan only operates on local disk — there's no "point it at a GitHub
URL" feature. The CI step always clones the repo first (which CI platforms
do automatically), then runs AgentScan against that checkout. Same pattern
on every platform:

```bash
agentscan agent agent.yaml --output sarif --output-file results.sarif   # → GitHub Security tab
agentscan agent agent.yaml --fail-on HIGH                                # → blocks PR merge
```

**GitHub Actions** — see [`.github/workflows/scan-on-pr.yml`](.github/workflows/scan-on-pr.yml).
Runs on every PR, scans both Python source and YAML/JSON configs, uploads
SARIF to the Security tab, comments findings.

**Bitbucket Pipelines** — see [`bitbucket-pipelines.yml`](bitbucket-pipelines.yml).
Bitbucket has no SARIF-native security tab, so this publishes the HTML
report as a build artifact and fails the pipeline on `--fail-on HIGH`.

**GitLab CI / Jenkins / other** — same three steps work anywhere with a
shell: `pip install`, `agentscan doctor .`, `agentscan source . --fail-on HIGH`.

## Sharing results — HTML dashboard

Every scan can produce a self-contained HTML report — no server, no database,
just a file you can open in any browser or email to someone:

```bash
agentscan source ./src/agents/ --output html --output-file report.html
```

Includes a risk score gauge, severity breakdown chart, attack paths, and a
filterable findings list with full evidence and fixes.

## Why this, not just a permission checklist

Most "AI agent security" advice is a checklist: *does your agent have shell access? does it
have secrets?* AgentScan instead asks the question an attacker actually asks: **starting from
a malicious prompt, what's the shortest path to something valuable?** That's the difference
between a list of yes/no flags and an actual attack graph with entry points, chains, and
blast radius.

## Evaluating AgentScan

```bash
agentscan demo                  # zero-setup: scan 11 vulnerable agents + 1 safe baseline
agentscan benchmark              # same suite, compact pass/fail table for CI
agentscan doctor ./your-repo/    # then: detects frameworks, tools, MCP servers in YOUR code
```

For a structured evaluation against known attack scenarios (the kind of
test a security team would run before approving any new tool), see
[`examples/vulnerable_agents/`](examples/vulnerable_agents/) — five
canonical attack chains plus a safe baseline, each with documented
expected output.

## Status

Early development. Core scanners (`agent`, `mcp`, `supply`) are stable and tested.
This repo also contains an experimental attack-graph engine, a compliance-mapping layer
(RBI/DPDP/ISO 42001), and a runtime monitoring SDK with framework integrations for
LangChain, CrewAI, AutoGen, and others — see [`docs/ADVANCED.md`](docs/ADVANCED.md) if
you want to go deeper.

Not yet on PyPI. Install from source:

```bash
git clone https://github.com/sneh2105/agentscan
cd agentscan
pip install -e ".[dev]"
agentscan agent examples/agent_configs/dangerous_agent.yaml
```

## Contributing

Issues and PRs welcome — especially additional agent config format support
(AutoGen, LangGraph, CrewAI native formats) and new MCP threat signatures.
See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache 2.0.
