# AgentScan Framework Examples

Runtime monitoring for every major AI agent framework.
Each example works standalone — run the demo functions without an API key.

## Quick start

```bash
pip install agentscan

# Run any demo without API key
python crewai_example.py
python autogen_example.py
python openai_agents_example.py
python google_adk_example.py
python semantic_kernel_example.py
python bedrock_agents_example.py
python langgraph_example.py
```

## Framework support matrix

| Framework | Integration style | Key file |
|---|---|---|
| **LangChain / LangGraph** | `BaseCallbackHandler` subclass | `langgraph_example.py` |
| **CrewAI** | Crew `callbacks` list | `crewai_example.py` |
| **AutoGen** | `register_reply` hook | `autogen_example.py` |
| **OpenAI Agents SDK** | Wrap pattern + hook | `openai_agents_example.py` |
| **Google ADK** | `before_model_callback` / `before_tool_callback` | `google_adk_example.py` |
| **Semantic Kernel** | `IPromptRenderFilter` + `IFunctionInvocationFilter` | `semantic_kernel_example.py` |
| **Amazon Bedrock Agents** | Trace stream parser | `bedrock_agents_example.py` |
| **Any framework** | Direct `AgentScanMonitor` API | `autogen_example.py` (demo section) |

## What gets monitored

Every framework integration captures the same events:

```
LLM Request       → what was sent to the model (including system prompt)
LLM Response      → what the model returned (including tool calls)
Tool Call         → which tool with which arguments
Tool Result       → what the tool returned (injection detection runs here)
Memory Read       → RAG retrieval queries and results
Network Call      → outbound HTTP requests
File Access       → filesystem read/write operations
Secret Access     → credential or secret retrievals
DB Query          → database queries
Process Spawn     → shell / subprocess commands
```

## What gets detected (in real time)

| Detection | Trigger |
|---|---|
| Prompt injection | `ignore previous instructions`, persona override, system token injection |
| Indirect injection | Injection pattern in tool result → subsequent tool call |
| Credential exposure | AWS key, OpenAI key, JWT, private key in any event |
| Credential exfiltration | Secret access → network call in same session |
| Dangerous commands | `curl \| bash`, `base64 -d`, crontab modification, netcat |
| Suspicious network | Calls to webhook.site, ngrok, requestbin, burpcollaborator |
| RAG override | Injection in retrieved documents that could override system prompt |

## Output options

```python
from agentscan.runtime.integrations.monitor import MonitorConfig

config = MonitorConfig(
    agent_name="my-agent",
    console_alerts=True,            # print to stderr immediately
    jsonl_path="events.jsonl",      # write every event as JSONL
    report_path="report.json",      # write final report on flush()
    webhook_url="https://...",      # POST alerts to SIEM/Slack/webhook
)
```

## Generic monitor API

Use this when your framework isn't in the list:

```python
from agentscan.runtime.integrations.monitor import AgentScanMonitor, MonitorConfig

monitor = AgentScanMonitor(MonitorConfig(agent_name="my-agent"))

# Log events as they happen
monitor.log_llm_request("gpt-4o", messages)
monitor.log_tool_call("search", {"query": "..."})
monitor.log_network_call("https://api.example.com/data", "GET")
monitor.log_tool_result("search", result_text)
monitor.log_secret_access("api-key-prod", source="vault")
monitor.log_llm_response(response_text)

# Flush at end of session
report = monitor.flush()

print(f"Critical findings: {sum(1 for f in report.findings if f.severity.value == 'CRITICAL')}")
for f in report.findings:
    print(f"  [{f.severity.value}] {f.title}")
    print(f"  Fix: {f.remediation}")
```

## CI/CD: scan before deploy, monitor after deploy

```bash
# Before deploy: static scan
agentscan agent ./agent_config.yaml --fail-on HIGH

# After deploy: analyse a recorded session
agentscan runtime analyse events.jsonl

# Identity check: what can this agent actually access?
agentscan runtime identity --config ./agent_config.yaml
```
