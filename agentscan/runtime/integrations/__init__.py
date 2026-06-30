"""
AgentScan Runtime Integrations
================================
Drop-in monitoring for AI agent frameworks.

Usage by framework:

  LangChain / LangGraph:
    from agentscan.runtime.integrations import AgentScanLangChainCallback
    agent.run(..., callbacks=[AgentScanLangChainCallback()])

  CrewAI:
    from agentscan.runtime.integrations import AgentScanCrewCallback
    crew = Crew(..., callbacks=[AgentScanCrewCallback()])

  AutoGen:
    from agentscan.runtime.integrations import AgentScanAutoGenHook
    hook = AgentScanAutoGenHook()
    agent.register_reply(hook.autogen_reply_hook, position=0)

  OpenAI Agents SDK:
    from agentscan.runtime.integrations import AgentScanOpenAIHook
    with agentscan_trace(agent_name="my-agent") as monitor:
        result = Runner.run_sync(agent, input)
        report = monitor.report()

  Bedrock / Generic:
    from agentscan.runtime.integrations import AgentScanMonitor
    monitor = AgentScanMonitor(agent_name="my-agent")
    monitor.log_llm_request(model, messages)
    monitor.log_tool_call(tool, args)
    ...
    report = monitor.flush()
"""

from agentscan.runtime.integrations.monitor import AgentScanMonitor, agentscan_trace
from agentscan.runtime.integrations.langchain_cb import AgentScanLangChainCallback
from agentscan.runtime.integrations.crewai_cb import AgentScanCrewCallback
from agentscan.runtime.integrations.autogen_hook import AgentScanAutoGenHook
from agentscan.runtime.integrations.openai_hook import AgentScanOpenAIHook

__all__ = [
    "AgentScanMonitor",
    "agentscan_trace",
    "AgentScanLangChainCallback",
    "AgentScanCrewCallback",
    "AgentScanAutoGenHook",
    "AgentScanOpenAIHook",
]
