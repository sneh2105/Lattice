# -*- coding: utf-8 -*-
"""
OpenAI Agents SDK Hook Integration
====================================
Usage:
    from agentscan.runtime.integrations import AgentScanOpenAIHook, agentscan_trace
    from openai_agents import Agent, Runner

    # Option 1: Context manager (recommended)
    hook = AgentScanOpenAIHook(agent_name="triage-agent")
    with hook.trace():
        result = Runner.run_sync(agent, input="user message")
    report = hook.flush()

    # Option 2: Wrap specific calls
    hook.before_agent_run(agent, input)
    result = Runner.run_sync(agent, input)
    hook.after_agent_run(result)
    report = hook.flush()
"""

from __future__ import annotations
from contextlib import contextmanager
from typing import Any, Generator
from agentscan.runtime.integrations.monitor import AgentScanMonitor, MonitorConfig
from agentscan.runtime.analyser import RuntimeAnalysisReport


class AgentScanOpenAIHook:
    """OpenAI Agents SDK monitoring via wrap pattern."""

    def __init__(
        self,
        agent_name: str = "openai-agent",
        monitor: AgentScanMonitor | None = None,
        console_alerts: bool = True,
        report_path: str | None = None,
    ):
        self._monitor = monitor or AgentScanMonitor(MonitorConfig(
            agent_name=agent_name,
            console_alerts=console_alerts,
            report_path=report_path,
        ))

    def before_agent_run(self, agent: Any, input_text: str) -> None:
        """Call before Runner.run_sync / Runner.run."""
        agent_name = getattr(agent, "name", str(agent))
        instructions = getattr(agent, "instructions", "")
        messages = []
        if instructions:
            messages.append({"role": "system", "content": str(instructions)})
        messages.append({"role": "user", "content": str(input_text)})
        self._monitor.log_llm_request(model=f"openai/{agent_name}", messages=messages)

    def after_agent_run(self, result: Any) -> None:
        """Call after Runner.run_sync / Runner.run."""
        output = ""
        if hasattr(result, "final_output"):
            output = str(result.final_output)
        elif hasattr(result, "output"):
            output = str(result.output)
        else:
            output = str(result)
        self._monitor.log_llm_response(content=output)

    def log_tool_call(self, tool_name: str, args: dict, result: Any = None) -> None:
        self._monitor.log_tool_call(tool=tool_name, args=args)
        if result is not None:
            self._monitor.log_tool_result(tool=tool_name, result=result)

    def log_handoff(self, from_agent: str, to_agent: str, context: str = "") -> None:
        """Log agent handoff events."""
        self._monitor.log_llm_request(
            model=f"handoff/{from_agent}→{to_agent}",
            messages=[{"role": "system", "content": f"Handoff: {from_agent} → {to_agent}. Context: {context}"}],
        )

    @contextmanager
    def trace(self) -> Generator[AgentScanMonitor, None, None]:
        try:
            yield self._monitor
        finally:
            pass

    def flush(self) -> RuntimeAnalysisReport:
        return self._monitor.flush()

    @property
    def monitor(self) -> AgentScanMonitor:
        return self._monitor
