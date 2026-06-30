"""
AgentScan + Microsoft Semantic Kernel
======================================
Monitors Semantic Kernel agents and pipelines.

Install:
    pip install semantic-kernel agentscan

Run:
    AZURE_OPENAI_KEY=... python semantic_kernel_example.py
"""

from agentscan.runtime.integrations.monitor import AgentScanMonitor, MonitorConfig


class AgentScanSKFilter:
    """
    Semantic Kernel filter for AgentScan monitoring.

    SK uses a filter pipeline (IPromptRenderFilter, IFunctionInvocationFilter).
    This class implements both interfaces.
    """

    def __init__(
        self,
        agent_name: str = "sk-agent",
        console_alerts: bool = True,
        report_path: str | None = None,
    ):
        self._monitor = AgentScanMonitor(MonitorConfig(
            agent_name=agent_name,
            console_alerts=console_alerts,
            report_path=report_path,
        ))

    # IPromptRenderFilter
    async def on_prompt_render(self, context: object, next_filter) -> None:
        """Intercept rendered prompts before they go to the LLM."""
        try:
            rendered = getattr(context, "rendered_prompt", "")
            if rendered:
                self._monitor.log_llm_request(
                    model="sk-model",
                    messages=[{"role": "user", "content": str(rendered)[:2000]}],
                )
        except Exception:
            pass
        if next_filter:
            await next_filter(context)

    # IFunctionInvocationFilter
    async def on_function_invocation(self, context: object, next_filter) -> None:
        """Intercept SK plugin function calls."""
        try:
            func = getattr(context, "function", None)
            func_name = getattr(func, "name", "unknown") if func else "unknown"
            plugin = getattr(func, "plugin_name", "") if func else ""
            full_name = f"{plugin}.{func_name}" if plugin else func_name
            args = {}
            if hasattr(context, "arguments"):
                args = {k: str(v) for k, v in (context.arguments or {}).items()}
            self._monitor.log_tool_call(tool=full_name, args=args)
        except Exception:
            pass

        if next_filter:
            await next_filter(context)

        try:
            result = getattr(context, "result", None)
            func_name = getattr(getattr(context, "function", None), "name", "unknown")
            if result is not None:
                self._monitor.log_tool_result(tool=func_name, result=str(result)[:500])
        except Exception:
            pass

    def flush(self):
        return self._monitor.flush()

    @property
    def monitor(self) -> AgentScanMonitor:
        return self._monitor


async def run_sk_agent(user_input: str) -> str:
    """Run a Semantic Kernel agent with AgentScan monitoring."""
    try:
        import semantic_kernel as sk
        from semantic_kernel.connectors.ai.open_ai import AzureChatCompletion
        from semantic_kernel.agents import ChatCompletionAgent
        from semantic_kernel.contents import ChatHistory
    except ImportError:
        raise ImportError("pip install semantic-kernel")

    monitor_filter = AgentScanSKFilter(
        agent_name="sk-support-agent",
        console_alerts=True,
        report_path="sk_security_report.json",
    )

    kernel = sk.Kernel()

    # Register service
    kernel.add_service(AzureChatCompletion(
        deployment_name="gpt-4o",
        api_key="YOUR_AZURE_KEY",
        endpoint="YOUR_AZURE_ENDPOINT",
    ))

    # Register AgentScan filters
    kernel.add_filter("prompt_render", monitor_filter.on_prompt_render)
    kernel.add_filter("function_invocation", monitor_filter.on_function_invocation)

    # Define a plugin (SK's equivalent of tools)
    class DocumentPlugin:
        @sk.kernel_function(name="search", description="Search documents")
        async def search(self, query: str) -> str:
            monitor_filter.monitor.log_memory_read(query=query)
            return f"Documents about: {query}"

        @sk.kernel_function(name="summarize", description="Summarise content")
        async def summarize(self, content: str) -> str:
            return f"Summary: {content[:100]}..."

    kernel.add_plugin(DocumentPlugin(), plugin_name="docs")

    agent = ChatCompletionAgent(
        kernel=kernel,
        name="document-assistant",
        instructions="Help users find and understand company documents.",
    )

    history = ChatHistory()
    history.add_user_message(user_input)

    try:
        result = ""
        async for chunk in agent.invoke(history):
            result += str(chunk.content)
    except Exception as e:
        result = f"API required. Error: {e}"

    report = monitor_filter.flush()
    print(f"\nSK Agent: {report.event_count} events, "
          f"{sum(1 for f in report.findings if f.severity.value == 'CRITICAL')} critical")
    return result


def demo_sk_monitoring():
    """Demo SK monitoring without API key."""
    monitor = AgentScanMonitor(MonitorConfig(agent_name="sk-demo", console_alerts=True))

    # Simulate SK pipeline events
    monitor.log_llm_request("azure-gpt-4o", [
        {"role": "system", "content": "You are a document assistant."},
        {"role": "user", "content": "Search for payroll data and export it."},
    ])
    monitor.log_tool_call("docs.search", {"query": "payroll data"})
    monitor.log_db_query("SELECT * FROM payroll WHERE year=2025", table="payroll")
    monitor.log_tool_result("docs.search", "Employee salaries: [DATA]")
    monitor.log_tool_call("email.send", {"to": "unknown@external.com", "body": "Payroll data attached"})
    monitor.log_network_call("https://smtp.external.com/send", "POST")

    report = monitor.flush()
    print(f"\nSK Demo: {report.event_count} events, {len(report.findings)} findings")
    for f in report.findings[:3]:
        print(f"  [{f.severity.value}] {f.title}")
    return report


if __name__ == "__main__":
    import asyncio
    print("=== Semantic Kernel + AgentScan Demo ===\n")
    demo_sk_monitoring()
