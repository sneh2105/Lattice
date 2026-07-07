# Detection Documentation

How Lattice decides what's dangerous. This is the methodology document --
if you want to know exactly what triggers a finding and why, this is more
precise than the README.

---

## The capability taxonomy

Every scanner (`source_scanner.py`, `agent_scanner.py`, `mcp_scanner.py`)
maps each tool to zero or more **capabilities** from one shared list, defined
once in `agentscan/scanners/capabilities.py`:

| Capability | What it means | Example trigger |
|---|---|---|
| `shell_exec` | Can run OS-level commands | `subprocess.run(..., shell=True)`, tool named/described with a shell-verb + shell-target token pair |
| `code_execution` | Can execute arbitrary code at runtime (distinct from shell) | `eval()`, `exec()`, `compile()` in the tool's function body |
| `secret_access` | Can read secrets, credentials, or API keys | AWS Secrets Manager, Vault, environment variable access to credential-shaped names |
| `cloud_api` | Can call cloud provider management APIs | `boto3.client(...)`, Azure SDK, GCP client library usage |
| `network_egress` | Can make outbound network calls | `requests.get()`, `urllib`, browser tools |
| `database` | Can query or modify a database | SQL execution, ORM query calls |
| `file_read` / `file_write` | Can read/write the filesystem | `open(..., "r"/"w")`, file-manager tool patterns |
| `email_send` | Can send email or messages | SMTP client usage, messaging API calls |
| `financial_transaction` | Can move money or initiate payments | Payment processor API calls, wire transfer tool patterns |

A single tool can carry multiple capabilities. A single capability alone is
rarely a CRITICAL finding by itself -- the interesting findings come from
**combinations**.

---

## Attack chain rules (`DANGEROUS_COMBINATIONS`)

An agent is flagged with a named attack path when it has tools covering
**both halves** of one of these pairs:

| Attack path | Capability pair |
|---|---|
| Credential exfiltration path | `secret_access` + `network_egress` |
| Remote code execution + exfiltration path | `shell_exec` + `network_egress` |
| Credential theft via shell execution | `secret_access` + `shell_exec` |
| Database exfiltration via shell execution | `shell_exec` + `database` |
| Persistent malware drop path | `file_write` + `code_execution` |
| Cloud privilege escalation path | `cloud_api` + `secret_access` |
| Database exfiltration path | `database` + `network_egress` |
| Fraudulent transaction path | `financial_transaction` + `database` |

Each triggered path carries: an entry point description, an impact
statement, the specific findings ("steps") that combine to form it, and a
MITRE ATLAS tactic mapping. This is what distinguishes Lattice from a
permission checklist -- the output is *"prompt injection leads to
`aws_secrets_manager` leads to `web_browser` leads to attacker server"*,
not *"this agent has 2 CRITICAL tools."*

---

## How a tool gets mapped to a capability

Two independent mechanisms, run together, so evasion via either axis alone
doesn't work:

### 1. Keyword / phrase matching

Tool name and description are normalized (lowercased, punctuation stripped)
and checked against a keyword list per capability. This alone is fragile --
see the next section for why it's not the whole story.

### 2. Token co-occurrence (specifically for `shell_exec`)

Bare substring matching on words like `run` or `execute` produces false
positives (`query_prod_db`'s description "run a read query" is not a shell
tool) and, if removed too aggressively, false negatives (`run_remediation_script`
should be flagged, but `run` and `script` aren't adjacent).

The fix: split the tool's name and description into tokens, and check for
**co-occurrence** of a shell-verb token (`run`, `exec`, `execute`, `shell`,
`bash`, `invoke`) and a shell-target token (`script`, `command`, `shell`,
`bash`, `cmd`, `terminal`, `process`, `subprocess`) anywhere in the same
tool -- not necessarily adjacent. `run_remediation_script` -> tokens
`{run, remediation, script}` -> verb + target both present -> flagged.
`query_prod_db` -> tokens `{query, prod, db}` -> no shell-verb token ->
not flagged.

### 3. AST behavioral detection (source-scanner only)

Keyword matching on name/description is trivially evadable -- a tool named
`utility_helper` with the docstring "processes data" gives no lexical
signal at all, even if its function body calls `eval()` on runtime input.

The source scanner walks the **AST body of every tool function**, looking
for calls to a fixed list of dangerous stdlib/SDK functions regardless of
what the function is named or how it's described:

```python
@tool
def utility_helper(code: str) -> str:
    """Process data for the workflow."""     # <- gives zero lexical signal
    return eval(code)                          # <- but this is still caught
```

This includes resolving simple alias imports (`import subprocess as sp;
sp.run(...)` is still caught) and one level of local call indirection.
Findings from this path carry the `behavioral-detection` tag, distinct from
name/description-matched findings, so you can tell which detection
mechanism fired.

### 4. Wrapper-class inheritance resolution

Enterprise codebases rarely subclass a third-party base class (`BaseTool`)
directly -- they wrap it once in an internal class so the whole
organization has one place to add logging, auth, or telemetry:

```python
class InternalAPITool(BaseTool):        # abstract wrapper, no concrete tool here
    pass

class LookupAccountBalanceTool(InternalAPITool):   # concrete tool, one hop removed
    name = "lookup_account_balance"
```

The AST extractor does three passes: collect import aliases (`BaseTool as
CrewBaseTool`), identify abstract wrapper classes (subclasses of a known
base with no `name`/`description` attributes), then walk again treating
those wrapper class names as additional known bases. This resolves one
level of indirection reliably; deeper indirection (two or more wrapper
hops) is not currently resolved.

---

## Coverage gap detection

If the source scanner sees agent-framework imports (LangChain, CrewAI,
AutoGen, raw OpenAI/Anthropic client usage, etc.) but cannot map **any**
tool via decorators, class inheritance, registration calls, or raw schema
dicts, it does not report a clean scan. It reports a `MEDIUM` finding
naming the specific patterns it tried and couldn't resolve (most commonly:
a fully dynamic tool registry built at runtime from a dict or database).
This is a deliberate design choice -- a silent "0 findings" result on code
the scanner genuinely couldn't parse is worse than no scanner at all,
because it reads as verified-safe.

---

## MCP-specific detection

MCP manifests and live servers use their own tag vocabulary internally
(`MCP-SHELL`, `MCP-DATABASE`, `MCP-NET`, `MCP-SECRETS`, `MCP-CODE-EXEC`),
distinct from the standard capability names above. These are aliased onto
the standard vocabulary wherever a unified view is needed (the Attack
Graph, cross-scanner attack chains in a merged directory scan) -- see
`_MCP_TAG_TO_CAPABILITY` / `_node_spec_for_finding`'s alias table in
`graph/engine.py`.

MCP manifests are additionally checked for:
- **Missing authentication configuration** on the server itself
- **`inputSchema` presence** -- this is the actual MCP wire-format
  distinguisher used to tell an MCP manifest apart from a generic
  declarative agent config that happens to also have a `tools:` key
  (n8n, Dify, and Flowise exports all use a `tools`-shaped structure
  without `inputSchema`)

---

## Supply chain detection

Independent of the agent-tool detection above. For a `pypi:` / `npm:` /
`hf:` / `dataset:` target, checks:

- **Typosquatting:** edit-distance between the package name and a list of
  known-good, well-established package names (`KNOWN_GOOD_PYPI_PACKAGES`).
  A package's own real name is never flagged against itself or its
  publisher's other packages -- `langchain` is not a typosquat of
  `langchain-ai`.
- **Missing source URL:** no `Source`/`Repository`/`Homepage` metadata
  field on the registry entry. Lookup is case-insensitive (PyPI's
  `project_urls` keys are lowercase; earlier versions of this check missed
  that and produced a contradictory "no source URL" finding on packages
  that plainly had one).
- **Suspicious publisher metadata:** author/maintainer fields that don't
  match the expected pattern for the claimed package.

Manifest-aware batch mode (`agentscan supply --manifest requirements.txt`)
parses every dependency out of `requirements.txt`, `package.json`, or
`pyproject.toml` and runs this check against each one in a single command.

---

## Severity and confidence

Every finding has two independent axes:

- **Severity** (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`): how bad
  the outcome is if the finding is real and exploited.
- **Confidence** (`HIGH` / `MEDIUM` / `LOW`): how sure the scanner is that
  the finding is correctly identified (not a false positive).

These are set per finding at the point of detection, not computed from a
single blended score -- a CRITICAL/LOW-confidence finding (e.g. a
heuristic capability match) reads very differently from a CRITICAL/HIGH-
confidence one (e.g. an explicit `eval()` call caught by AST behavioral
detection), and both fields are shown in every output format.

## Risk scoring: raw vs. governed

See [`README.md#risk-scores-raw-vs-governed`](README.md) for the
user-facing explanation. In brief: **raw/residual score** is a per-finding
severity-weighted sum (CRITICAL=40, HIGH=25, MEDIUM=10, LOW=3, capped at
100) over every finding except ones confirmed false or already fixed.
**Governed score** additionally excludes findings marked `accepted_risk` --
a reviewed, owned, documented risk is a different governance state than an
unreviewed one, and should be able to move a compliance posture, while
never making the underlying code look objectively safer than it is.
