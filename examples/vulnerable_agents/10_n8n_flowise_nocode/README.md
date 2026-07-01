# Scenario 10 — n8n and Flowise no-code workflow exports

**Attack chain:** Shell + secret + database tools defined inside visual
workflow builders — no Python source code at all.

## Setup
n8n and Flowise are visual workflow automation platforms. n8n adds
AI Agent nodes to business automation workflows; Flowise builds
LangChain-backed agent flows via drag-and-drop. Both export to JSON
that AgentScan's recursive tool-list detector handles.

## Run
```bash
agentscan agent n8n_workflow.json
agentscan agent flowise_export.json
```

## Expected result
- n8n: risk **100/100**, shell_exec + database + credential exfiltration attack paths
- Flowise: risk **100/100**, ShellExecutor (CRITICAL), SecretRetriever (CRITICAL)

## How it works
The recursive fallback in `agent_scanner.py` walks the nested JSON
structure looking for list-shaped collections of tool definitions,
regardless of the surrounding schema. This catches both n8n's
`nodes[*].parameters.tools` nesting and Flowise's `nodes[*].data.tools`.
