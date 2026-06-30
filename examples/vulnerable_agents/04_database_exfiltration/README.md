# Scenario 04 — Database exfiltration via MCP server

**Attack chain:** MCP server with DB query tool + network tool, no authentication

## Setup
An MCP manifest exposing both database query and HTTP request tools, with
no authentication configured.

## Run
```bash
agentscan mcp mcp_server.json
agentscan graph mcp mcp_server.json   # trust + risk scoring
```

## Expected result
- Trust score: **LOW or CRITICAL** (no auth penalty)
- Risk score: **≥60/100**
- Attack path: cross-tool database exfiltration
- Finding: "MCP server has no authentication configured"

## The fix
Require OAuth 2.0 or API key auth on every MCP server. Scope database
tools to read-only, specific tables. Add network egress allowlisting.
