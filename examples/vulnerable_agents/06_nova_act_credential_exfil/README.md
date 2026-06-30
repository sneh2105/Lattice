# Scenario 06 — Amazon Nova Act: credential access + shell execution

**Attack chain:** Browser automation workflow → AWS credential tool + shell diagnostic tool → host compromise

## Setup
Amazon Nova Act uses the same `@tool` decorator convention as LangChain
and CrewAI ([AWS docs](https://docs.aws.amazon.com/nova-act/latest/userguide/tool-use.html)),
so AgentScan's source scanner detects Nova Act tools without any
framework-specific code. This scenario mirrors a realistic Nova Act
workflow with a credential-retrieval tool and a shell diagnostic tool
defined alongside the browser automation logic.

## Run
```bash
agentscan source nova_act_agent.py
```

## Expected result
- Risk score: **100/100**
- CRITICAL findings: `fetch_aws_credentials` (secret_access), `run_shell_diagnostic` (shell_exec)
- Multiple attack paths including credential exfiltration and RCE chains
- Framework correctly identified as `langchain_crewai_or_nova_act`

## A known limitation found via this test
Source-extracted findings use keyword matching against tool docstrings.
Nova Act docstrings frequently mention "browser automation" — which can
trigger a network_egress false-positive flag on tools that don't actually
touch the network. All source-scanned findings carry MEDIUM confidence
(not HIGH) for exactly this reason, and findings explicitly note
"verify this matches the tool's actual runtime behaviour."

## The fix
Never combine credential retrieval and shell execution capability in the
same workflow. Use Nova Act's built-in state guardrails (domain
allowlisting) and restrict tool registration to only what the specific
workflow run actually needs.
