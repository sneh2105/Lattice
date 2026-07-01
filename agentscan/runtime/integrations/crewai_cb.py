# -*- coding: utf-8 -*-
"""
CrewAI Callback Integration
============================
Usage:
    from agentscan.runtime.integrations import AgentScanCrewCallback

    callback = AgentScanCrewCallback(agent_name="research-crew")
    crew = Crew(
        agents=[researcher, writer],
        tasks=[task1, task2],
        callbacks=[callback],
        verbose=True,
    )
    result = crew.kickoff()
    report = callback.flush()
"""

from __future__ import annotations
from typing import Any
from agentscan.runtime.integrations.monitor import AgentScanMonitor, MonitorConfig
from agentscan.runtime.analyser import RuntimeAnalysisReport


class AgentScanCrewCallback:
    """
    CrewAI callback handler.
    CrewAI uses a simpler callback interface than LangChain.
    """

    def __init__(
        self,
        agent_name: str = "crew-agent",
        monitor: AgentScanMonitor | None = None,
        console_alerts: bool = True,
        report_path: str | None = None,
        webhook_url: str | None = None,
    ):
        self._monitor = monitor or AgentScanMonitor(MonitorConfig(
            agent_name=agent_name,
            console_alerts=console_alerts,
            report_path=report_path,
            webhook_url=webhook_url,
        ))
        self._current_agent: str = agent_name

    # CrewAI callback interface
    def on_task_start(self, task: Any, agent: Any = None, **kwargs) -> None:
        agent_name = getattr(agent, "role", str(agent)) if agent else self._current_agent
        self._current_agent = agent_name
        task_desc = getattr(task, "description", str(task))
        self._monitor.log_llm_request(
            model=f"crewai/{agent_name}",
            messages=[{"role": "user", "content": task_desc}]
        )

    def on_task_end(self, output: Any, task: Any = None, **kwargs) -> None:
        result = getattr(output, "raw", str(output)) if output else ""
        self._monitor.log_llm_response(content=str(result))

    def on_tool_use_start(self, tool: Any, input_str: str = "", agent: Any = None, **kwargs) -> None:
        tool_name = getattr(tool, "name", str(tool))
        try:
            import json
            args = json.loads(input_str) if input_str and input_str.startswith("{") else {"input": input_str}
        except Exception:
            args = {"input": str(input_str)}
        self._monitor.log_tool_call(tool=tool_name, args=args)

    def on_tool_use_end(self, tool: Any, output: str = "", **kwargs) -> None:
        tool_name = getattr(tool, "name", str(tool))
        self._monitor.log_tool_result(tool=tool_name, result=str(output))

    def on_agent_action(self, action: str = "", agent: Any = None, **kwargs) -> None:
        """Called for agent reasoning steps."""
        pass  # Reasoning logs are informational — not surfaced as events

    def flush(self) -> RuntimeAnalysisReport:
        return self._monitor.flush()

    @property
    def monitor(self) -> AgentScanMonitor:
        return self._monitor
