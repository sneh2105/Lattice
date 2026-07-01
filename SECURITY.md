# Security Policy

## Reporting a vulnerability

If you find a security issue in AgentScan itself, please **do not open a public
GitHub issue**. Instead, email **sneh2105@github.com** (or open a
[GitHub private security advisory](https://github.com/sneh2105/agentscan/security/advisories/new)).

Include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact

You should receive a response within 72 hours. If it's a real issue I'll
coordinate a fix before any public disclosure.

## Scope

AgentScan is a static analysis tool — it reads files, it doesn't execute agent
code. The main attack surfaces in AgentScan itself are:

- **Malicious YAML/JSON inputs** — a crafted agent config that causes AgentScan
  to crash or behave incorrectly. YAML parsing uses PyYAML's safe_load() throughout.
- **Path traversal** — `agentscan source ./some/path` should not read outside
  the given directory. Confirmed by test.
- **The HTML report output** — all user-controlled strings are HTML-escaped before
  being written into the report. XSS-escaping is tested.

## What this project is NOT

AgentScan scans *your* agent code for security issues. It is not itself an agent,
does not make LLM calls, and does not send your code or configs anywhere —
everything runs locally. There is no telemetry, no phone-home, no cloud component.
