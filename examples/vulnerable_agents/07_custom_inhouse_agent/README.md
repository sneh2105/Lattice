# Scenario 07 — Custom in-house agent (no named framework)

**Attack chain:** Shell execution + secret access + database access, defined
via raw Anthropic/OpenAI native tool schema — no LangChain, CrewAI, AutoGen,
or any third-party SDK at all.

## Why this scenario exists

Not every company building agents uses a named framework. Many larger
enterprises — especially those with strict security/compliance review
processes that slow third-party dependency adoption — build their own
thin orchestration layer directly on the Anthropic or OpenAI API. Tools
are defined as raw dicts matching the API's native schema:

```python
TOOLS = [
    {"name": "execute_shell", "description": "...", "input_schema": {...}},
]
```

This is the single most common pattern for in-house agent code, since
it requires no dependency at all — just the official API client.

## Run
```bash
agentscan source internal_agent.py
```

## Expected result
- Risk score: **100/100**
- CRITICAL findings: `execute_shell` (shell_exec), `get_aws_secret` (secret_access)
- Attack path: cloud privilege escalation
- Framework correctly identified as `raw_api_tool_schema`

## The fix
Same as any other framework — least privilege, no shell access combined
with secret access, sandbox execution. The point of this scenario isn't a
different fix, it's proving AgentScan doesn't require a named framework
to find the same class of risk.
