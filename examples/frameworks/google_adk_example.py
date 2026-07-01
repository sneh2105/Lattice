# -*- coding: utf-8 -*-
"""
AgentScan + Google Agent Development Kit (ADK)
================================================
Monitors Google ADK agents for security events.

Install:
    pip install google-adk agentscan

Google ADK uses a callback/event system. AgentScan wraps it via
the generic monitor API with a Google-ADK-specific adapter.

Run:
    GOOGLE_API_KEY=... python google_adk_example.py
"""

from agentscan.runtime.integrations.monitor import AgentScanMonitor, MonitorConfig, agentscan_trace


class AgentScanGoogleADKCallback:
    """
    Google ADK callback adapter for AgentScan.

    Google ADK exposes lifecycle hooks via subclassing or callback registration.
    This class bridges ADK events to AgentScan monitor calls.
    """

    def __init__(
        self,
        agent_name: str = "google-adk-agent",
        monitor: AgentScanMonitor | None = None,
        console_alerts: bool = True,
        report_path: str | None = None,
    ):
        self._monitor = monitor or AgentScanMonitor(MonitorConfig(
            agent_name=agent_name,
            console_alerts=console_alerts,
            report_path=report_path,
        ))

    # Google ADK callback interface
    def on_before_model(self, callback_context: object, llm_request: object) -> None:
        """Called before each model invocation."""
        try:
            model = getattr(llm_request, "model", "gemini")
            contents = getattr(llm_request, "contents", [])
            messages = []
            for c in (contents or []):
                role = getattr(c, "role", "user")
                parts = getattr(c, "parts", [])
                text = " ".join(getattr(p, "text", str(p)) for p in (parts or []))
                messages.append({"role": role, "content": text})
            self._monitor.log_llm_request(model=str(model), messages=messages)
        except Exception:
            self._monitor.log_llm_request(model="gemini", messages=[])

    def on_after_model(self, callback_context: object, llm_response: object) -> None:
        """Called after model responds."""
        try:
            candidates = getattr(llm_response, "candidates", [])
            content = ""
            if candidates:
                parts = getattr(getattr(candidates[0], "content", None), "parts", [])
                content = " ".join(getattr(p, "text", str(p)) for p in (parts or []))
            self._monitor.log_llm_response(content=content)
        except Exception:
            self._monitor.log_llm_response(content=str(llm_response))

    def on_before_tool(self, tool: object, args: dict, tool_context: object) -> None:
        """Called before each tool invocation."""
        tool_name = getattr(tool, "name", str(tool))
        self._monitor.log_tool_call(tool=tool_name, args=args or {})

    def on_after_tool(self, tool: object, args: dict, tool_context: object, result: object) -> None:
        """Called after tool completes."""
        tool_name = getattr(tool, "name", str(tool))
        self._monitor.log_tool_result(tool=tool_name, result=str(result))

    def flush(self):
        return self._monitor.flush()

    @property
    def monitor(self):
        return self._monitor


def run_google_adk_agent(user_input: str) -> str:
    """Run a Google ADK agent with AgentScan monitoring."""
    try:
        from google.adk.agents import Agent
        from google.adk.runners import Runner
        from google.adk.sessions import InMemorySessionService
        import google.generativeai as genai
    except ImportError:
        raise ImportError("pip install google-adk google-generativeai")

    callback = AgentScanGoogleADKCallback(
        agent_name="google-adk-research",
        console_alerts=True,
        report_path="google_adk_security_report.json",
    )

    # Tool definitions
    def search_documents(query: str) -> str:
        """Search internal documents."""
        callback.monitor.log_tool_call("search_documents", {"query": query})
        result = f"Document results for: {query}"
        callback.monitor.log_tool_result("search_documents", result)
        return result

    def get_policy(policy_name: str) -> str:
        """Retrieve a company policy document."""
        callback.monitor.log_memory_read(query=f"policy:{policy_name}")
        result = f"Policy '{policy_name}': [policy content]"
        callback.monitor.log_tool_result("get_policy", result)
        return result

    # Build agent
    agent = Agent(
        model="gemini-2.0-flash",
        name="document-assistant",
        instruction=(
            "You are a document assistant. Help users find information "
            "in company documents and policies."
        ),
        tools=[search_documents, get_policy],
        before_model_callback=callback.on_before_model,
        after_model_callback=callback.on_after_model,
        before_tool_callback=callback.on_before_tool,
        after_tool_callback=callback.on_after_tool,
    )

    session_service = InMemorySessionService()
    runner = Runner(agent=agent, app_name="doc-assistant", session_service=session_service)

    try:
        from google.adk.sessions import Session
        session = session_service.create_session(app_name="doc-assistant", user_id="user-1")
        from google.genai import types
        content = types.Content(role="user", parts=[types.Part(text=user_input)])
        events = list(runner.run(user_id="user-1", session_id=session.id, new_message=content))
        output = events[-1].content.parts[0].text if events else ""
    except Exception as e:
        output = f"API key required. Error: {e}"

    report = callback.flush()
    print(f"\nAgentScan: {report.event_count} events, "
          f"{sum(1 for f in report.findings if f.severity.value == 'CRITICAL')} critical findings")
    return output


# ── Demo without API key ──────────────────────────────────────────────────────

def demo_without_api_key():
    """Simulate ADK agent events for demo/testing."""
    monitor = AgentScanMonitor(MonitorConfig(agent_name="google-adk-demo", console_alerts=True))

    monitor.log_llm_request("gemini-2.0-flash", [
        {"role": "user", "content": "Find the employee salary policy and email it to me."},
    ])
    monitor.log_tool_call("search_documents", {"query": "salary policy"})
    monitor.log_memory_read(query="salary policy")
    monitor.log_tool_result("search_documents", "Salary ranges: Junior $60k-$80k, Senior $100k-$150k, VP $180k+")
    monitor.log_tool_call("send_email", {"to": "external@example.com", "content": "Salary data: ..."})
    monitor.log_network_call("https://mail.external.com/send", "POST")

    report = monitor.flush()
    print(f"\nDemo: {report.event_count} events, {len(report.findings)} findings")
    for f in report.findings[:3]:
        print(f"  [{f.severity.value}] {f.title}")
    return report


if __name__ == "__main__":
    print("=== Google ADK + AgentScan Demo ===\n")
    demo_without_api_key()
