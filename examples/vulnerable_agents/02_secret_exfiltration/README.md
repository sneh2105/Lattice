# Scenario 02 — Credential exfiltration

**Attack chain:** Prompt injection → secret retrieval tool → network egress tool → attacker server

## Setup
An agent that can retrieve AWS secrets AND make outbound HTTP requests.
A single injected instruction can chain these into a complete exfiltration path.

## Run
```bash
agentscan agent agent.yaml
```

## Expected result
- Risk score: **≥70/100**
- CRITICAL findings for `aws_secrets_manager` and `web_browser`
- Attack path: "Credential exfiltration path"
- MITRE ATLAS: AML.T0051, AML.T0040

## The fix
Never combine secret access and network egress in the same agent. If both
are needed, use separate agents with no shared context, or require human
approval before any network call that follows a secret retrieval.
