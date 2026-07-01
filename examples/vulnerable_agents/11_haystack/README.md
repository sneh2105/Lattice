# Scenario 11 — Haystack

**Attack chain:** Shell + database + secret tools registered via
Haystack's `Tool(name=..., function=..., description=...)` API.

## Setup
Haystack is deepset's production-ready Python orchestration framework
with 23k GitHub stars. Its tool registration pattern matches the
generic `Tool(...)` call pattern AgentScan already detects for
LangChain — so Haystack tools are caught without framework-specific code.

## Run
```bash
agentscan source haystack_agent.py
```

## Expected result
- Risk score: **100/100**
- CRITICAL: `execute_system_command` (shell_exec), `get_secret_from_vault` (secret_access)
- HIGH: `query_production_database` (database)
- Framework label: `langchain_or_haystack` (both use the same Tool() pattern)
