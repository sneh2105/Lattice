<div align="center">

# Lattice

**Find the shortest path to what matters.**

A security scanner for AI agents and MCP servers that doesn't just list permissions --
it shows you the complete chain from a malicious prompt to a stolen credential.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-274%20passing-brightgreen)](tests/)

[Threat Model](THREAT_MODEL.md) · [Architecture](ARCHITECTURE.md) · [Detection Methodology](DETECTION.md) · [CLI Reference](CLI_REFERENCE.md) · [Benchmarks](BENCHMARKS.md) · [Roadmap](ROADMAP.md)

</div>

---

## The problem

Every AI agent framework lets you bolt on tools -- shell access, database queries, web browsing,
secret retrieval. Each tool looks fine in isolation. Nobody checks what happens when an agent
has three or four of them *at once*, and a prompt injection chains them together.

```yaml
tools:
  - name: aws_secrets_manager   # "we need this for deployment automation"
  - name: web_browser           # "we need this for research"
```

Individually, reasonable. Together: a complete credential exfiltration path that a single
malicious prompt can trigger.

## Why this, not just a permission checklist

Most "AI agent security" advice is a checklist: *does your agent have shell access? does it
have secrets?* Lattice instead asks the question an attacker actually asks: **starting from
a malicious prompt, what's the shortest path to something valuable?** That's the difference
between a list of yes/no flags and an actual attack graph with entry points, chains, and
blast radius. See [`THREAT_MODEL.md`](THREAT_MODEL.md) for the precise attacker model and
scope boundaries.

## Try it with zero setup

No agent of your own handy? Run Lattice against 12 intentionally
vulnerable agents -- no cloning, no config, just installed and run:

```bash
pip install -e .
agentscan demo
```

```
  Prompt injection -> shell
  An agent with browser + shell tools -- a malicious web page can hijack it into running commands
  [OK] Risk 56/100  -  1 attack path(s) found
    Remote code execution + exfiltration path
  ...
  Safe scoped search agent
  [OK] Risk 0/100  -  0 finding(s) -- no false positives

  [OK] Lattice correctly identified all 12 attack patterns with zero false positives.
```

`agentscan benchmark` runs the same suite in a compact pass/fail table -- see
[`BENCHMARKS.md`](BENCHMARKS.md) for full results and methodology, and
[`examples/vulnerable_agents/`](examples/vulnerable_agents/) for what each
scenario tests and why.

## Supported frameworks

LangChain · LangGraph · CrewAI · AutoGen · OpenAI Agents SDK ·
Google ADK · Semantic Kernel · Amazon Bedrock Agents · Amazon Nova Act ·
PydanticAI · LlamaIndex · Haystack · MCP ·
n8n · Flowise · Dify · No framework (raw Anthropic/OpenAI schemas)

`agentscan source` scans Python agent code via AST -- `@tool`, `@agent.tool`,
`@agent.tool_plain`, `@function_tool`, `@sk.kernel_function`, `BaseTool` subclasses
(including internal wrapper-class inheritance), `FunctionTool.from_defaults()`,
`register_function()`, and raw `TOOLS = [{"name": ..., "input_schema": {...}}]`
API schemas. It also catches dangerous behavior a name/description would never
reveal -- a tool named `utility_helper` calling `eval()` in its body still gets
flagged. See [`DETECTION.md`](DETECTION.md) for exactly how.

`agentscan agent` scans YAML/JSON configs including Dify, n8n, and Flowise workflow
exports. `agentscan mcp` scans MCP servers live or from a manifest.

**Not yet covered:** Mastra (TypeScript -- no TS AST parser yet) and AI gateway
config (Bifrost, TrueFoundry, Cloudflare AI Gateway governance rules).
See [`ROADMAP.md`](ROADMAP.md) and [`THREAT_MODEL.md`](THREAT_MODEL.md#explicitly-out-of-scope).

## What Lattice does

Real agents live in real code -- LangChain, CrewAI, AutoGen -- not in YAML files.
Lattice reads that code directly, with zero execution:

```bash
agentscan source ./src/agents/   # scans an entire repo for tool definitions
```

It parses `@tool` decorators, `BaseTool` subclasses, and `register_function()` calls
across LangChain, CrewAI, and AutoGen patterns via Python's AST -- no agent execution,
no API key required, works on a clone of your repo.

If you'd rather describe an agent declaratively (e.g. for a deploy-time gate, or an
agent that genuinely is config-driven), `agentscan agent` accepts YAML/JSON directly:

```
  Lattice ──────────────────────────────────────────
  Risk score  100/100  [####################]

  Findings: 2 CRITICAL  3 HIGH  5 MEDIUM
  Attack paths: 4 critical chain(s) found

  +== ATTACK PATHS ============================================+
  |  1. Credential exfiltration path
  |     Entry : Prompt injection via user input or malicious tool output
  |     Impact: AWS/cloud credentials, API keys exfiltrated to attacker
  |     Chain : web_browser -> aws_secrets_manager
  |     ATLAS : AML.T0051, AML.T0040
  +=============================================================+

  [X CRITICAL] Tool 'aws_secrets_manager' grants secret access
               [confidence: HIGH]

  What's happening:
    The tool 'aws_secrets_manager' maps to the 'secret_access' capability.
    In combination with network tools, this forms a complete attack chain.

  Fix:
    Review whether this tool is required. Scope its permissions as narrowly
    as possible. Consider running the agent in a sandboxed environment.

  MITRE ATLAS: AML.T0051
```

No false-positive noise on harmless tools (calculator, weather lookup, search) -- tested and
verified zero CRITICAL/HIGH findings on innocuous capabilities. Every finding ships with
the exact evidence that triggered it and a concrete fix, mapped to MITRE ATLAS.

## MCP server scanning

```bash
agentscan mcp your_mcp_manifest.json
agentscan mcp https://your-mcp-server.com   # scans a live server
```

Same attack-path detection, applied to MCP tool definitions -- catches servers that combine
shell execution, credential access, and network egress into a single exploit chain.

## The dashboard

```bash
agentscan ui
```

Starts a local web dashboard -- no separate install, no cloud account. Paste
a GitHub URL and it clones and scans automatically, drop local files, or
point at a live MCP endpoint. Includes:

- **Attack Graph** -- interactive D3 visualization of the actual exploit chain
- **Findings** -- full evidence, fix, and MITRE mapping per finding, with a
  per-finding disposition picker (see below)
- **Compliance** -- posture and control mapping across 7 regulatory frameworks
- **Supply Chain** -- auto-reads `requirements.txt`/`package.json`/`pyproject.toml`
  from the scanned target and batch-scans every dependency, no manual entry required
- **Export** -- PDF audit report, SARIF, JSON, Markdown, plus drift baseline
  capture/compare

Runs entirely on `localhost`. Nothing leaves your machine except the three
network calls documented in [`THREAT_MODEL.md`](THREAT_MODEL.md#threat-model-for-lattice-itself)
(package registry lookups, a live MCP URL you provide, and `git clone` for
the GitHub input mode).

## Risk disposition: accept, dispute, or close a finding

A re-scan of unchanged code shouldn't force a team to re-litigate the same
finding every time. Every finding can be set to one of four states, each
requiring a reason and a reviewer name:

| Status | Meaning | Effect on score |
|---|---|---|
| `open` | Default -- unreviewed | Counts fully |
| `accepted_risk` | Reviewed, tolerated with a documented compensating control | Excluded from **governed** score only -- the risk objectively still exists, so it stays in the raw/residual score |
| `false_positive` | Confirmed the finding is wrong | Removed from **every** score -- it was never a real risk |
| `remediated` | Confirmed fixed | Removed from every score, flagged for re-verification on the next scan |

This is why Lattice reports **two** numbers, not one:

- **Residual technical risk** -- what the code objectively still exposes
  (includes accepted risks; excludes confirmed false positives and fixes)
- **Governed risk (post-review)** -- what a CISO or auditor should actually
  act on (excludes everything that's been reviewed and dispositioned)

Accepting a risk must never make the code look safer than it is -- only a
confirmed false positive or a confirmed fix should move the residual number.
Dispositioned findings never disappear from a report; they move to a
visible "resolved" section with the full audit trail (who, when, why).

## Compliance and audit reporting

```bash
agentscan compliance map <target>
agentscan compliance dpia <target>
agentscan compliance audit <target> --organisation "Acme Corp" --output-file audit.pdf
```

Maps findings to specific controls across RBI AI-ACT&RS, DPDP Rules 2025,
ISO 42001, EU AI Act, NIST AI RMF, SOC 2, and SEBI CSCRF. Generates a full
PDF: executive summary with residual/governed risk score, findings table,
control mapping, DPIA, and a risk acceptance register. Only genuinely open
findings count toward the compliance posture and score -- see
[`DETECTION.md#risk-scoring-raw-vs-governed`](DETECTION.md#risk-scoring-raw-vs-governed).

## Comparing scans over time

```bash
agentscan diff <target> --save-baseline
agentscan diff <target> --fail-on-new         # CI gate: exit 1 if anything new appeared
```

Fingerprint-based drift detection -- findings are matched by ID and tags,
not exact wording, so a re-worded description doesn't look like a new
issue. Reports new / resolved / escalated / de-escalated / unchanged counts.

## CI/CD integration

Lattice only operates on local disk -- there's no "point it at a GitHub
URL" feature at the CLI level (the dashboard's clone-and-scan is a
separate, browser-driven workflow). The CI step always clones the repo
first (which CI platforms do automatically), then runs Lattice against
that checkout. Same pattern on every platform:

```bash
agentscan agent agent.yaml --output sarif --output-file results.sarif   # -> GitHub Security tab
agentscan agent agent.yaml --fail-on HIGH                                # -> blocks PR merge
agentscan diff agent.yaml --fail-on-new                                  # -> blocks PR on new findings only
```

**GitHub Actions** -- see [`.github/workflows/scan-on-pr.yml`](.github/workflows/scan-on-pr.yml).
Runs on every PR, scans both Python source and YAML/JSON configs, uploads
SARIF to the Security tab, comments findings.

**Bitbucket Pipelines** -- see [`bitbucket-pipelines.yml`](bitbucket-pipelines.yml).
Bitbucket has no SARIF-native security tab, so this publishes the HTML
report as a build artifact and fails the pipeline on `--fail-on HIGH`.

**GitLab CI / Jenkins / other** -- same steps work anywhere with a
shell: `pip install`, `agentscan doctor .`, `agentscan source . --fail-on HIGH`.

Full command reference: [`CLI_REFERENCE.md`](CLI_REFERENCE.md).

## Supply chain scanning

```bash
agentscan supply pypi:langchain
agentscan supply --manifest requirements.txt      # batch-scans every dependency in one call
```

Typosquatting detection, missing-source-URL checks, and suspicious
publisher metadata across PyPI, npm, HuggingFace models, and datasets.
Manifest-aware mode reads `requirements.txt`, `package.json`, or
`pyproject.toml` directly -- no need to name each package individually.

## Documentation

| Document | What's in it |
|---|---|
| [`THREAT_MODEL.md`](THREAT_MODEL.md) | The precise attacker model, what's in/out of scope, Lattice's own attack surface |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Pipeline overview, module map, key design decisions and why |
| [`DETECTION.md`](DETECTION.md) | Exact detection methodology -- capability taxonomy, attack chain rules, AST behavioral detection, scoring math |
| [`CLI_REFERENCE.md`](CLI_REFERENCE.md) | Every command, every flag |
| [`BENCHMARKS.md`](BENCHMARKS.md) | Current benchmark results, adversarial test coverage, test suite breakdown |
| [`ROADMAP.md`](ROADMAP.md) | What's stable, what's in progress, what's explicitly not planned and why |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | How to add framework support, extend detection, add compliance frameworks |
| [`SECURITY.md`](SECURITY.md) | How to report a vulnerability in Lattice itself |

## Status

Core scanners (`agent`, `mcp`, `source`, `supply`) and the dashboard are
stable and tested (274 tests, 12/12 benchmark scenarios). The runtime
monitoring SDK is functional but less mature -- see [`ROADMAP.md`](ROADMAP.md)
for the full breakdown of what's production-ready versus actively hardened.

Not yet on PyPI. Install from source:

```bash
git clone https://github.com/sneh2105/agentscan
cd agentscan
pip install -e ".[dev]"
agentscan agent examples/agent_configs/dangerous_agent.yaml
```

## Contributing

Issues and PRs welcome -- especially additional agent config format support
and new MCP threat signatures. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

Apache 2.0.

---

<div align="center">
by sneh with sneh &lt;3
</div>
