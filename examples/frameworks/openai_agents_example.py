"""
AgentScan + OpenAI Agents SDK
==============================
Monitors OpenAI Agents with handoffs and tool calls.

Install:
    pip install openai-agents agentscan

Run:
    OPENAI_API_KEY=sk-... python openai_agents_example.py
"""

from agentscan.runtime.integrations import AgentScanOpenAIHook
from agentscan.runtime.integrations.monitor import AgentScanMonitor, MonitorConfig, agentscan_trace


# ── OpenAI Agents SDK integration ─────────────────────────────────────────────

def run_triage_system(user_input: str) -> str:
    """
    Run an OpenAI Agents triage system with monitoring.
    Triage → (handoff to) Specialist Agent.
    """
    try:
        from openai_agents import Agent, Runner, function_tool, handoff
    except ImportError:
        raise ImportError("pip install openai-agents")

    hook = AgentScanOpenAIHook(
        agent_name="triage-system",
        console_alerts=True,
        report_path="openai_agents_security_report.json",
    )

    # Tool definitions
    @function_tool
    def search_kb(query: str) -> str:
        """Search the knowledge base."""
        hook.log_tool_call("search_kb", {"query": query})
        result = f"KB results: {query}"
        hook.monitor.log_tool_result("search_kb", result)
        return result

    @function_tool
    def get_account_info(account_id: str) -> dict:
        """Get customer account details."""
        hook.log_tool_call("get_account_info", {"account_id": account_id})
        result = {"id": account_id, "tier": "enterprise", "balance": 50000}
        hook.monitor.log_tool_result("get_account_info", result)
        return result

    @function_tool
    def escalate_to_human(reason: str, priority: str = "medium") -> str:
        """Escalate conversation to human agent."""
        hook.log_tool_call("escalate_to_human", {"reason": reason, "priority": priority})
        result = f"Escalated: {reason}"
        hook.monitor.log_tool_result("escalate_to_human", result)
        return result

    # Specialist agents
    billing_agent = Agent(
        name="billing-specialist",
        instructions="Handle billing enquiries, refunds, and account adjustments. Be precise.",
        tools=[get_account_info, escalate_to_human],
    )

    technical_agent = Agent(
        name="technical-specialist",
        instructions="Handle technical issues, bugs, and integration questions.",
        tools=[search_kb, escalate_to_human],
    )

    # Triage agent with handoffs
    triage_agent = Agent(
        name="triage",
        instructions=(
            "You are the first point of contact. Understand the customer issue "
            "and route to the appropriate specialist. "
            "For billing issues → billing-specialist. "
            "For technical issues → technical-specialist."
        ),
        handoffs=[
            handoff(billing_agent),
            handoff(technical_agent),
        ],
    )

    # Monitor the full run
    hook.before_agent_run(triage_agent, user_input)

    try:
        result = Runner.run_sync(triage_agent, input=user_input)
        hook.after_agent_run(result)
        output = str(result.final_output)
    except Exception as e:
        output = f"API key required for full run. Error: {e}"
        # Still log a simulated response for demo
        hook.monitor.log_llm_response(
            content="Routing to billing specialist.",
        )
        hook.log_handoff("triage", "billing-specialist", user_input)

    report = hook.flush()

    print(f"\n{'='*60}")
    print("AgentScan — OpenAI Agents SDK Security Report")
    print(f"{'='*60}")
    print(f"Events   : {report.event_count}")
    print(f"Critical : {sum(1 for f in report.findings if f.severity.value == 'CRITICAL')}")
    for f in report.findings:
        print(f"  [{f.severity.value}] {f.title}")

    return output


# ── Minimal example: just the monitor ─────────────────────────────────────────

def minimal_monitoring_example():
    """
    Minimal: wrap any OpenAI Agents run with agentscan_trace.
    No hooks needed — use the monitor's log_* API directly.
    """
    with agentscan_trace("openai-minimal", console_alerts=True) as monitor:
        # Log what you know about the run
        monitor.log_llm_request("gpt-4o", [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "What's the weather in London?"},
        ])
        monitor.log_tool_call("get_weather", {"city": "London"})
        monitor.log_network_call("https://api.weather.com/london", "GET")
        monitor.log_tool_result("get_weather", {"temp": 18, "condition": "cloudy"})
        monitor.log_llm_response("It's 18°C and cloudy in London.")

    print("Session complete. Report written.")


if __name__ == "__main__":
    print("=== OpenAI Agents SDK + AgentScan ===\n")
    minimal_monitoring_example()
    print("\nFor full triage system (requires API key):")
    print("  result = run_triage_system('I was charged twice for my subscription')")
