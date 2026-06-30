# Safe baseline — scoped search agent

**No attack chain.** This is the negative control: a well-scoped agent
that should produce zero CRITICAL/HIGH findings.

## Run
```bash
agentscan agent agent.yaml
```

## Expected result
- Risk score: **0/100**
- 0 findings
- 0 attack paths

If AgentScan flags this as risky, that's a false positive — please file an issue.
