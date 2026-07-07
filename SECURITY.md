# Security Policy

## Reporting a vulnerability

If you find a security issue in Lattice itself, please **do not open a
public GitHub issue**. Instead, email **sneh2105@gmail.com** (or open a
[GitHub private security advisory](https://github.com/sneh2105/agentscan/security/advisories/new)).

Include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact

You should receive a response within 72 hours. If it's a real issue I'll
coordinate a fix before any public disclosure.

## Scope

Lattice is primarily a static analysis tool -- it reads files, it doesn't
execute agent code. As of v0.4.x it also includes a local web dashboard
and a GitHub clone-and-scan feature, which widen the attack surface
somewhat. The full breakdown of what Lattice touches, what runs locally
vs. makes network calls, and how each surface is defended is documented in
[`THREAT_MODEL.md`](THREAT_MODEL.md#threat-model-for-lattice-itself) --
that's the authoritative reference; this file is the short version.

- **Malicious YAML/JSON inputs** -- parsed via PyYAML's `safe_load()`
  throughout, never the unsafe default loader.
- **Malicious Python source as scan input** -- never executed. Parsed via
  `ast.parse()` only; Lattice never calls `exec()`/`eval()` on scanned code
  or imports it as a module.
- **Path traversal** -- `agentscan source ./some/path` should not read
  outside the given directory. Confirmed by test.
- **GitHub clone-and-scan (dashboard)** -- clones with `git clone --depth 1`
  into an isolated temp directory scoped to that scan; nothing inside the
  clone is ever executed.
- **HTML report output** -- all user-controlled strings are HTML-escaped
  before being written into the report. XSS-escaping is tested.
- **PDF report output** -- finding text is escaped before being passed to
  ReportLab's `Paragraph()`, which otherwise interprets a subset of
  HTML-like markup.
- **The local dashboard server** -- binds to `localhost` only, on a random
  free port by default. Not intended to be exposed to a network.
- **Outbound network calls** -- limited to three code paths:
  `agentscan supply` (package registry APIs), `agentscan mcp <url>` (the
  specific server URL you provide), and the dashboard's GitHub clone
  feature. `agentscan source` and `agentscan agent` make zero network calls.
- **Risk acceptance register** (`~/.agentscan/risk_register.json`) and
  **drift baselines** (`~/.agentscan/baselines/`) -- plain JSON on local
  disk, unencrypted, readable by any process running as the same user.

## What this project is NOT

Lattice scans *your* agent code for security issues. It is not itself an
agent, does not make LLM calls, and does not send your code or configs
anywhere -- everything runs locally except the three explicitly-listed
network code paths above. There is no telemetry, no phone-home, no cloud
component.
