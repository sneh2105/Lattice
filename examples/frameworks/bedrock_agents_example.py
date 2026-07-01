# -*- coding: utf-8 -*-
"""
AgentScan + Amazon Bedrock Agents
===================================
Monitors AWS Bedrock Agents invocations for security events.

Install:
    pip install boto3 agentscan

Run:
    AWS_DEFAULT_REGION=us-east-1 python bedrock_agents_example.py

Note: Bedrock Agents return trace data in the response stream.
AgentScan parses this trace to reconstruct the event chain.
"""

import json
from typing import Any
from agentscan.runtime.integrations.monitor import AgentScanMonitor, MonitorConfig


class AgentScanBedrockAdapter:
    """
    Adapter for AWS Bedrock Agents.

    Bedrock Agents don't have a traditional callback system --
    instead, all events come back in the response stream as trace objects.

    This adapter:
    1. Wraps the boto3 invoke_agent call
    2. Parses the trace stream as it arrives
    3. Feeds events to AgentScanMonitor in real time
    4. Returns both the agent output and the security report
    """

    def __init__(
        self,
        agent_name: str = "bedrock-agent",
        console_alerts: bool = True,
        report_path: str | None = None,
        webhook_url: str | None = None,
    ):
        self._monitor = AgentScanMonitor(MonitorConfig(
            agent_name=agent_name,
            console_alerts=console_alerts,
            report_path=report_path,
            webhook_url=webhook_url,
        ))

    def invoke_agent(
        self,
        bedrock_client: Any,
        agent_id: str,
        agent_alias_id: str,
        session_id: str,
        input_text: str,
        enable_trace: bool = True,
    ) -> tuple[str, Any]:
        """
        Invoke a Bedrock Agent and monitor the full trace.

        Returns: (agent_output, security_report)
        """
        # Log the initial request
        self._monitor.log_llm_request(
            model=f"bedrock/{agent_id}",
            messages=[{"role": "user", "content": input_text}],
        )

        try:
            response = bedrock_client.invoke_agent(
                agentId=agent_id,
                agentAliasId=agent_alias_id,
                sessionId=session_id,
                inputText=input_text,
                enableTrace=enable_trace,
            )
        except Exception as e:
            return f"Error: {e}", self._monitor.flush()

        # Parse the streaming response
        output_text = ""
        for event in response.get("completion", []):
            self._parse_bedrock_event(event)
            if "chunk" in event:
                output_text += event["chunk"].get("bytes", b"").decode("utf-8", errors="ignore")

        # Log the final response
        self._monitor.log_llm_response(content=output_text)

        report = self._monitor.flush()
        return output_text, report

    def _parse_bedrock_event(self, event: dict) -> None:
        """Parse a single Bedrock trace event and log to monitor."""
        trace = event.get("trace", {})
        if not trace:
            return

        orchestration = trace.get("orchestrationTrace", {})

        # Model invocation
        model_input = orchestration.get("modelInvocationInput", {})
        if model_input:
            text = model_input.get("text", "")
            if text:
                self._monitor.log_llm_request(
                    model="bedrock-claude",
                    messages=[{"role": "user", "content": text[:1000]}],
                )

        model_output = orchestration.get("modelInvocationOutput", {})
        if model_output:
            content = ""
            raw = model_output.get("rawResponse", {})
            if raw:
                try:
                    body = json.loads(raw.get("content", "{}"))
                    content = str(body.get("content", ""))
                except Exception:
                    content = str(raw)
            self._monitor.log_llm_response(content=content[:500])

        # Tool/action invocations
        invocation = orchestration.get("invocationInput", {})
        if invocation:
            action_group = invocation.get("actionGroupInvocationInput", {})
            if action_group:
                func = action_group.get("function", "unknown")
                params = action_group.get("parameters", [])
                args = {p.get("name"): p.get("value") for p in params}
                self._monitor.log_tool_call(tool=func, args=args)

            # Knowledge base retrieval (RAG)
            kb_input = invocation.get("knowledgeBaseLookupInput", {})
            if kb_input:
                query = kb_input.get("text", "")
                self._monitor.log_memory_read(query=query)

        # Tool results
        observation = orchestration.get("observation", {})
        if observation:
            action_result = observation.get("actionGroupInvocationOutput", {})
            if action_result:
                self._monitor.log_tool_result(
                    tool="action_group",
                    result=str(action_result.get("text", ""))[:500],
                )
            kb_result = observation.get("knowledgeBaseLookupOutput", {})
            if kb_result:
                refs = kb_result.get("retrievedReferences", [])
                results = [r.get("content", {}).get("text", "")[:100] for r in refs]
                self._monitor.log_memory_read(query="(kb result)", results=results)

        # Guard rail trace
        guard_trace = trace.get("guardrailTrace", {})
        if guard_trace:
            action = guard_trace.get("action", "")
            if action == "INTERVENED":
                self._monitor.log_llm_response(
                    content=f"[GUARDRAIL BLOCKED: {guard_trace.get('inputAssessment', '')}]"
                )


def run_bedrock_agent(user_input: str) -> str:
    """Run a Bedrock Agent with full AgentScan monitoring."""
    try:
        import boto3
    except ImportError:
        raise ImportError("pip install boto3")

    adapter = AgentScanBedrockAdapter(
        agent_name="bedrock-support-agent",
        console_alerts=True,
        report_path="bedrock_security_report.json",
    )

    client = boto3.client("bedrock-agent-runtime", region_name="us-east-1")

    output, report = adapter.invoke_agent(
        bedrock_client=client,
        agent_id="YOUR_AGENT_ID",
        agent_alias_id="TSTALIASID",
        session_id="session-001",
        input_text=user_input,
    )

    print(f"\nBedrock Agent: {report.event_count} events, "
          f"{sum(1 for f in report.findings if f.severity.value == 'CRITICAL')} critical")
    return output


def demo_bedrock_monitoring():
    """Demo Bedrock monitoring without AWS credentials."""
    monitor = AgentScanMonitor(MonitorConfig(agent_name="bedrock-demo", console_alerts=True))

    # Simulate Bedrock trace events
    monitor.log_llm_request("bedrock-claude-3-5-sonnet", [
        {"role": "user", "content": "Retrieve our customer database and send a summary to marketing@acme.com"},
    ])
    monitor.log_memory_read(query="customer database")
    monitor.log_tool_call("customer_db_query", {"query": "SELECT * FROM customers LIMIT 10000"})
    monitor.log_db_query("SELECT * FROM customers LIMIT 10000", table="customers")
    monitor.log_tool_result("customer_db_query", "10000 customer records retrieved")
    monitor.log_tool_call("send_email", {"to": "marketing@acme.com", "subject": "Customer Data", "body": "..."})
    monitor.log_network_call("https://ses.us-east-1.amazonaws.com/send", "POST")

    report = monitor.flush()
    print(f"\nBedrock Demo: {report.event_count} events, {len(report.findings)} findings")
    for f in report.findings[:3]:
        print(f"  [{f.severity.value}] {f.title}")
    return report


if __name__ == "__main__":
    print("=== Amazon Bedrock Agents + AgentScan Demo ===\n")
    demo_bedrock_monitoring()
