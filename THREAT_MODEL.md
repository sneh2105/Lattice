# Threat Model

This document describes what Lattice defends against, what it explicitly does
not, and the assumptions it makes about the systems it scans. If you're
evaluating Lattice for a security program, this is the document to read before
the README.

---

## What we're modeling

An AI agent is not a static program. It is an LLM with tools, and the LLM's
behavior is influenced by anything in its context: the system prompt, the
user's message, and — critically — **the output of any tool it calls**. That
last part is the part most security reviews miss.

Lattice models one specific attacker capability: **the ability to inject
instructions into an agent's context**, and asks what that attacker can reach
from there.

### The attacker

- Does **not** have credentials, API keys, or direct system access.
- **Can** control or influence one of:
  - The end-user's prompt (direct prompt injection)
  - The content of a web page, document, email, or API response the agent
    reads or browses (indirect prompt injection)
  - A tool's return value, if that tool queries untrusted external data
    (e.g. a "fetch URL" tool retrieving attacker-controlled content)
  - An MCP server's tool description or manifest, if the attacker can stand
    up or compromise an MCP server the agent is configured to trust

### The question we answer

*Starting from that single point of control, what is the shortest path to
something valuable — credentials, PII, money, code execution, or an
external network destination?*

This is a fundamentally different question from "does this agent have a
tool with shell access?" A tool inventory tells you what's possible in
isolation. An attack graph tells you what's reachable from an attacker's
actual entry point, through the actual chain of tools available, to an
actual target worth stealing.

---

## In scope

| Threat | How Lattice detects it |
|---|---|
| **Prompt injection to credential exfiltration** | A tool with `secret_access` combined with any tool granting `network_egress` in the same agent |
| **Prompt injection to remote code execution** | `shell_exec` combined with `network_egress`, or standalone `shell_exec`/`code_execution` findings from AST behavioral detection |
| **Cloud privilege escalation** | `secret_access` combined with `cloud_api` (e.g. an AWS Secrets Manager client that also has IAM-adjacent permissions) |
| **Data exfiltration via database access** | `database` combined with `network_egress`, or `database` combined with `shell_exec` |
| **Financial fraud chains** | `financial_transaction` combined with `database` (an agent that can both look up account data and move money) |
| **Persistent malware / backdoor installation** | `file_write` combined with `code_execution` |
| **Evasion via indirection** | Wrapper-class inheritance (`InternalTool(BaseTool)` then `ConcreteTool(InternalTool)`), aliased imports, one-hop function wrapping -- all resolved via AST body-walking, not name-matching |
| **Evasion via vague naming** | Behavioral detection: a tool named `utility_helper` with a bland docstring is still flagged if its function body calls `eval()`, `subprocess.run()`, `boto3.client("secretsmanager")`, etc. -- detection reads what the code *does*, not what it's *called* |
| **Missing MCP server authentication** | Explicit check for auth configuration on every scanned MCP manifest |
| **Compromised/malicious dependencies** | Supply chain scanner: typosquatting detection (edit-distance against known-good package names), missing source URL, suspicious metadata, on PyPI/npm/HuggingFace/dataset registries |
| **Silent detection gaps** | If Lattice sees agent-framework imports but can't map any tool registration pattern (e.g. a fully dynamic runtime registry), it reports a `MEDIUM` "coverage gap" finding -- never a false "clean" result |

---

## Explicitly out of scope

Being honest about these boundaries is itself a security property -- a tool
that implies it covers everything is more dangerous than one that's precise
about its limits.

| Not covered | Why | What to use instead |
|---|---|---|
| **Runtime prompt injection detection** | Lattice is a static analyzer. It cannot see what an actual production conversation contains. | Runtime guardrails (Lakera Guard, LLM Guard, NeMo Guardrails) sit in the live traffic path |
| **Model-level red-teaming** | Lattice doesn't call any LLM API and doesn't evaluate model outputs. | Garak, Promptfoo, PyRIT -- adversarial prompt suites against a live model |
| **The LLM's own alignment/safety** | Out of scope by design -- that's the model provider's responsibility, not the agent's tool configuration | N/A |
| **TypeScript/Mastra agents** | No TS AST parser yet | Manual review, or contribute a parser (see CONTRIBUTING.md) |
| **AI gateway governance config** (Bifrost, TrueFoundry, Cloudflare AI Gateway) | These are infrastructure layers; Lattice scans the application code on either side, not the gateway's own routing/allow-list config | Review gateway config directly against vendor docs |
| **Runtime session analysis** (actual conversation transcripts, live tool call sequences) | Different data shape entirely -- partially addressed by `agentscan runtime analyse`, a separate and less mature subsystem | Treat static scan results as pre-deployment gating, not a substitute for production monitoring |
| **Network-level attacks** (MITM, DNS spoofing, TLS downgrade against the agent's actual API calls) | Not a code-level property | Standard network security controls |

---

## Assumptions and their failure modes

Every static analyzer makes assumptions. Here are ours, stated so you can
decide whether they hold for your codebase.

**Assumption: tool registration is discoverable via AST.**
Fails if tools are registered via a fully dynamic mechanism the static
analyzer can't resolve at parse time (e.g. tool names loaded from a
database at runtime, or constructed via string concatenation and `eval`).
Mitigation: Lattice detects this failure mode itself -- if it sees
framework imports but can't map any tools, it emits a `MEDIUM`
"coverage gap" finding rather than a false-clean result. See
[`DETECTION.md`](DETECTION.md#coverage-gap-detection).

**Assumption: a tool's docstring/name/AST body reflects its actual runtime behavior.**
Fails if a tool calls into a compiled extension, a subprocess that itself
does something dangerous three layers down, or dynamically imports a module
whose contents aren't visible in the scanned file. Lattice's behavioral
detection (AST body-walking) catches the common single-hop cases --
`eval()`, `subprocess.run()`, dynamic `getattr()` dispatch -- but cannot see
through an opaque compiled binary or a genuinely dynamic
`importlib.import_module(user_input)`.

**Assumption: capability combinations are dangerous when co-present in one agent.**
This is a heuristic, not a proof. An agent with `secret_access` and
`network_egress` is flagged as a credential-exfiltration risk even if, in
practice, the two tools are never callable in the same conversation turn
due to application-level logic Lattice doesn't model (e.g. a state machine
that only exposes one tool at a time). This is a deliberate false-positive
tradeoff: we'd rather flag a theoretical chain a human reviewer dismisses
in five seconds than silently miss a real one.

**Assumption: MITRE ATLAS tactic mappings are reference points, not certifications.**
The `AML.T0051` / `AML.T0040` / etc. tags describe the *category* of
technique a finding resembles. They are not a claim that MITRE has reviewed
or endorsed this specific finding.

---

## Threat model for Lattice itself

Lattice is a tool that reads (and in the dashboard's case, clones) code you
may not fully trust. Its own attack surface matters.

- **Malicious YAML/JSON input:** parsed via PyYAML's `safe_load()` throughout
  -- never `yaml.load()` with the default (unsafe) loader.
- **Malicious Python source (as scanned input):** never executed. Lattice
  parses Python via `ast.parse()`, walks the syntax tree, and never calls
  `exec()`, `eval()`, or imports the scanned code as a module.
- **Malicious GitHub repos (dashboard's clone-and-scan feature):** cloned
  with `git clone --depth 1` into an isolated temp directory scoped to that
  scan. Lattice does not execute anything inside the clone -- it only walks
  the file tree and parses source/config files.
- **The local dashboard server:** binds to `localhost` only (not `0.0.0.0`),
  on a randomly assigned free port by default. It is not intended to be
  exposed to a network -- see [`ARCHITECTURE.md`](ARCHITECTURE.md) for the
  server lifecycle.
- **Outbound network calls:** only three code paths make them --
  `agentscan supply` (PyPI/npm/HuggingFace/dataset registry APIs),
  `agentscan mcp <url>` (the specific MCP server URL you provide), and the
  dashboard's GitHub clone feature (`git clone` to the URL you provide).
  `agentscan source` and `agentscan agent` make zero network calls.
- **HTML report XSS:** all user-controlled strings (tool names, descriptions
  pulled from scanned code) are HTML-escaped before being written into
  generated reports. Tested explicitly.
- **PDF report injection:** finding text is escaped before being passed to
  ReportLab's `Paragraph()`, which otherwise interprets a subset of HTML-like
  markup -- an unescaped tool description containing an anchor tag could
  otherwise inject a live hyperlink into a board-facing PDF.
- **Risk acceptance register file** (`~/.agentscan/risk_register.json`):
  plain JSON on local disk, no encryption, readable by any process running
  as the same user. Do not use it to store anything more sensitive than a
  finding ID, a reviewer name, and a written justification.

See [`SECURITY.md`](SECURITY.md) for how to report a vulnerability in
Lattice itself.
