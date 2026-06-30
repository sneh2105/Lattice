# Scenario 03 — Direct shell execution in real source code

**Attack chain:** Tool docstring describes shell access → AST scanner detects it directly from code

## Setup
A real Python file (not YAML) using a LangChain `@tool` decorator on a
function that calls `subprocess.run()`. Tests the source code scanner path,
not the declarative config path.

## Run
```bash
agentscan source devops_agent.py
```

## Expected result
- Risk score: **≥40/100**
- 1 CRITICAL finding for `run_command`, with exact file:line location
- MITRE ATLAS: AML.T0017

## The fix
Review whether shell access is genuinely required. Sandbox execution.
Add command allowlisting. Never let LLM-generated text become a raw
shell command.
