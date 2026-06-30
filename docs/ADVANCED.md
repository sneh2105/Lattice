# AgentScan — Advanced Capabilities

The README covers the core scanner. This document covers everything else built on top of it.
These modules are functional and tested but less battle-tested than the core scanners —
expect rough edges, and please file issues.

## Attack Graph Engine

Every scan can be represented as a real directed graph — nodes for tools, resources,
entry points, and crown jewels; edges for data flow and execution paths — with BFS
reachability, path scoring, and blast radius analysis.

```bash
agentscan graph agent ./agent.yaml
agentscan graph agent ./agent.yaml --export-html graph.html   # interactive D3.js graph
```

### AI-SQL — query the attack graph directly

```bash
agentscan graph query ./agent.yaml "CAN user_prompt ACCESS aws_credentials"
agentscan graph query ./agent.yaml "BLAST RADIUS OF user_prompt"
agentscan graph query ./agent.yaml "FIND crown_jewel WHERE reachable_from = 'user_prompt'"
```

### Capability Escalation Analysis

Cloud-IAM-style privilege escalation detection for AI capabilities. Finds when
declared "low-risk" capabilities combine into hidden, undeclared ones —
e.g. `file_read` effectively grants `secret_access` (credential files live on disk),
`shell_exec` effectively grants everything.

```bash
agentscan graph escalation ./agent.yaml
```

### Trust Flow Graph

Taint-tracking for LLM context: traces how untrusted data (user input, tool results,
RAG documents) flows toward privileged actions, flagging every crossing that lacks
a validation step.

```bash
agentscan graph trustflow ./agent.yaml
```

### Multi-server trust chains

Models trust propagation when an agent (or MCP server) calls other MCP servers —
catches "safe" servers that are actually polluted by a dangerous downstream dependency.

```bash
agentscan graph chain server_a.json server_b.json --calls "A→B"
```

## Runtime Monitoring

Static scanning tells you what an agent *could* do. Runtime monitoring tells you
what it *actually did*. SDK with drop-in integrations for major frameworks.

```python
from agentscan.runtime.integrations import AgentScanLangChainCallback

callback = AgentScanLangChainCallback(agent_name="support-bot", report_path="report.json")
agent_executor.invoke({"input": user_input}, config={"callbacks": [callback]})
report = callback.flush()
```

Framework integrations: LangChain/LangGraph, CrewAI, AutoGen, OpenAI Agents SDK,
Google ADK, Semantic Kernel, Amazon Bedrock Agents — see [`examples/frameworks/`](../examples/frameworks/).

Detects in real time: prompt injection (direct and indirect via tool results),
credential exposure, credential-to-network exfiltration chains, dangerous shell
commands, and calls to known interception domains (webhook.site, ngrok, etc.).

```bash
agentscan runtime analyse session.json     # analyse a recorded event log
agentscan runtime flow --config agent.yaml --has-rag   # prompt data-flow analysis
agentscan runtime identity --config agent.yaml          # "what can this agent actually access?"
agentscan runtime goals session.json                     # reasoning/goal-drift detection
```

### Reasoning & Goal Integrity Analysis

Detects when an agent's behaviour drifts from its declared goal — even without an
explicit injection string. A "summarise documents" agent that ends up calling
`shell_exec` is a structural red flag regardless of what triggered it.

## Compliance

Maps every finding to specific controls across RBI (AI-ACT&RS, MRM 2026), DPDP Act 2023,
SEBI CSCRF, ISO 42001, EU AI Act, NIST AI RMF, and SOC 2 — built for teams that need to
produce audit evidence, not just fix bugs.

```bash
agentscan compliance map ./agent.yaml             # which controls does this violate?
agentscan compliance dpia ./agent.yaml            # generate a Data Protection Impact Assessment
agentscan compliance audit ./agent.yaml \
  --organisation "Acme Bank" --output-file audit.pdf   # board-ready PDF report
```

## AI Supply Chain Scanning

```bash
agentscan supply pypi:some-package
agentscan supply npm:some-package
agentscan supply hf:org/model-name
agentscan supply dataset:org/dataset-name    # scans for prompt-injection poisoning in dataset rows
```

---

## Why so much surface area?

This started as a focused scanner and grew into a research platform exploring what
comprehensive AI agent security tooling could look like end-to-end — from static config
scanning through runtime monitoring to compliance reporting. The core scanner (covered in
the main README) is the stable, recommended entry point. Everything here is the deeper
bench for teams that want more, or for security researchers who want to see the full
architecture.

Feedback on which of these modules is actually useful in practice is extremely welcome —
open an issue.
