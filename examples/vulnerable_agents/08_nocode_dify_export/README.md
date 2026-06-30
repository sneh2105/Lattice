# Scenario 08 — No-code platform export (Dify-style)

**Attack chain:** Shell execution + secret access tools defined inside a
no-code visual workflow builder export — no Python source code at all.

## Why this scenario exists

Platforms like Dify let non-engineers build agents through a drag-and-drop
interface. There is no source code to AST-scan — the "agent" exists as a
nested YAML/JSON workflow export, with tools identified by `tool_name` /
`provider_id` fields instead of the `name` / `description` convention
used by code-based frameworks.

This is a structurally different problem from the other scenarios: it's
not about recognising a new decorator or SDK call, it's about correctly
parsing a declarative export format with different field names, nested
several levels deep.

## Run
```bash
agentscan agent dify_export.yml
```

## Expected result
- Risk score: **100/100**
- CRITICAL findings: `execute_shell_command` (shell_exec), `get_secret_from_vault` (secret_access)
- HIGH finding: `query_database` (database)

## A known limitation
This scenario is handled via two mechanisms: explicit Dify DSL path
recognition (`model_config.agent_mode.tools`), and a generic recursive
fallback that searches the whole config tree for tool-shaped lists. The
fallback is intentionally conservative — it requires both a name-like key
(`name`/`tool_name`/`provider_id`/`id`) and a description-like key
(`description`/`tool_description`/`provider_type`) before treating a
nested list as tool definitions, to avoid false-positiving on unrelated
nested data (user lists, settings, etc.). Other no-code platforms with
substantially different export shapes (Emergent, n8n, Zapier-style
workflows) are NOT yet explicitly tested — if you hit one that isn't
detected, please file an issue with an anonymised export sample.

## The fix
Same principle as code-based agents: review every tool granted to the
workflow, remove unnecessary shell/secret access, and apply the
platform's own permission scoping (Dify supports per-tool authorization
scopes) rather than relying on default broad access.
