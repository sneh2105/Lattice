# -*- coding: utf-8 -*-
"""
AutoGen Hook Integration
=========================
Usage:
    from agentscan.runtime.integrations import AgentScanAutoGenHook
    import autogen

    hook = AgentScanAutoGenHook(agent_name="autogen-system")

    # Option 1: register_reply hook (AutoGen 0.2+)
    assistant = autogen.AssistantAgent("assistant", llm_config=llm_config)
    hook.attach(assistant)

    # Option 2: wrap initiate_chat
    with hook.trace():
        user_proxy.initiate_chat(assistant, message=user_message)

    report = hook.flush()
"""

from __future__ import annotations
from contextlib import contextmanager
from typing import Any, Generator
from agentscan.runtime.integrations.monitor import AgentScanMonitor, MonitorConfig
from agentscan.runtime.analyser import RuntimeAnalysisReport


class AgentScanAutoGenHook:
    """AutoGen monitoring via register_reply hooks."""

    def __init__(
        self,
        agent_name: str = "autogen-agent",
        monitor: AgentScanMonitor | None = None,
        console_alerts: bool = True,
        report_path: str | None = None,
    ):
        self._monitor = monitor or AgentScanMonitor(MonitorConfig(
            agent_name=agent_name,
            console_alerts=console_alerts,
            report_path=report_path,
        ))
        self._attached: list[Any] = []

    def attach(self, agent: Any, position: int = 0) -> None:
        """
        Attach to an AutoGen agent via register_reply.
        Works with AssistantAgent, UserProxyAgent, ConversableAgent.
        """
        if not hasattr(agent, "register_reply"):
            raise ValueError(f"Agent {agent} does not have register_reply -- is autogen installed?")

        monitor = self._monitor

        def _reply_hook(
            recipient: Any,
            messages: list[dict] | None = None,
            sender: Any = None,
            config: Any = None,
        ) -> tuple[bool, Any]:
            """Intercepts every message exchange."""
            if messages:
                # Log the incoming messages as LLM request
                getattr(sender, "name", "user") if sender else "user"
                model = getattr(getattr(recipient, "llm_config", None), "get", lambda k, d: d)("model", "gpt-4")
                monitor.log_llm_request(
                    model=str(model),
                    messages=[{"role": "user", "content": str(m.get("content", ""))} for m in messages[-3:]],
                )
            return False, None  # False = don't override, let AutoGen continue normally

        agent.register_reply(
            trigger=lambda sender: True,
            reply_func=_reply_hook,
            position=position,
        )
        self._attached.append(agent)

    def log_function_call(self, func_name: str, args: dict, result: Any = None) -> None:
        """Call when an AutoGen function/tool is invoked."""
        self._monitor.log_tool_call(tool=func_name, args=args)
        if result is not None:
            self._monitor.log_tool_result(tool=func_name, result=result)

    @contextmanager
    def trace(self) -> Generator[AgentScanMonitor, None, None]:
        """Wrap an initiate_chat block."""
        try:
            yield self._monitor
        finally:
            pass  # Don't flush here -- user calls flush() manually

    def flush(self) -> RuntimeAnalysisReport:
        return self._monitor.flush()

    @property
    def monitor(self) -> AgentScanMonitor:
        return self._monitor
