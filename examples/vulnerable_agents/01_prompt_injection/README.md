# Scenario 01 — Prompt injection to shell execution

**Attack chain:** User prompt → agent → shell_exec tool → OS command execution

## Setup
An agent with both a web browsing tool (untrusted content source) and a shell
execution tool. A malicious instruction embedded in a scraped web page or
tool result can hijack the agent into running arbitrary commands.

## Run
```bash
agentscan agent agent.yaml
```

## Expected result
- Risk score: **≥50/100**
- At least 1 **CRITICAL** finding for `shell_exec`
- At least 1 attack path: "Remote code execution + exfiltration path"
- MITRE ATLAS: AML.T0017, AML.T0040

## The fix
Remove `shell_exec` if not strictly required. If required, sandbox it,
allowlist permitted commands, and never let untrusted content (web pages,
tool results) reach the prompt context unsanitised.
