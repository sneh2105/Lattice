"""
LangChain / LangGraph Callback Integration
===========================================
Drop-in callback handler for LangChain agents and LangGraph graphs.

Usage:
    # LangChain agent
    from agentscan.runtime.integrations import AgentScanLangChainCallback

    callback = AgentScanLangChainCallback(agent_name="support-bot")
    agent_executor.invoke({"input": user_input}, config={"callbacks": [callback]})
    report = callback.flush()

    # LangGraph (StateGraph)
    from langgraph.graph import StateGraph
    graph = StateGraph(...)
    graph.compile()
    result = graph.invoke(state, config={"callbacks": [callback]})

    # With agentscan_trace
    with agentscan_trace("support-bot") as monitor:
        callback = AgentScanLangChainCallback(monitor=monitor)
        agent.invoke(input, config={"callbacks": [callback]})
"""

from __future__ import annotations
from typing import Any, Union
from uuid import UUID

from agentscan.runtime.integrations.monitor import AgentScanMonitor, MonitorConfig, agentscan_trace
from agentscan.runtime.analyser import RuntimeAnalysisReport


class AgentScanLangChainCallback:
    """
    LangChain BaseCallbackHandler compatible class.
    Works with LangChain agents, chains, and LangGraph.

    Designed to not fail silently — if LangChain is not installed,
    the class still works but won't auto-register as a BaseCallbackHandler.
    """

    def __init__(
        self,
        agent_name: str = "langchain-agent",
        monitor: AgentScanMonitor | None = None,
        console_alerts: bool = True,
        report_path: str | None = None,
        webhook_url: str | None = None,
    ):
        if monitor:
            self._monitor = monitor
        else:
            self._monitor = AgentScanMonitor(MonitorConfig(
                agent_name=agent_name,
                console_alerts=console_alerts,
                report_path=report_path,
                webhook_url=webhook_url,
            ))
        self._current_tool: str | None = None

        # Try to inherit from LangChain BaseCallbackHandler if available
        try:
            from langchain_core.callbacks.base import BaseCallbackHandler
            # Monkey-patch the class into a proper subclass at runtime
            self.__class__.__bases__ = (BaseCallbackHandler,)
        except ImportError:
            pass

    # ── LLM callbacks ─────────────────────────────────────────────────────────

    def on_llm_start(self, serialized: dict, prompts: list[str], **kwargs) -> None:
        model = serialized.get("id", ["unknown"])[-1] if serialized.get("id") else "unknown"
        messages = [{"role": "user", "content": p} for p in prompts]
        self._monitor.log_llm_request(model=model, messages=messages)

    def on_chat_model_start(self, serialized: dict, messages: list[list], **kwargs) -> None:
        model = serialized.get("id", ["unknown"])[-1] if serialized.get("id") else "unknown"
        flat = []
        for msg_list in messages:
            for msg in msg_list:
                if hasattr(msg, "type") and hasattr(msg, "content"):
                    flat.append({"role": msg.type, "content": str(msg.content)})
                elif isinstance(msg, dict):
                    flat.append(msg)
        self._monitor.log_llm_request(model=model, messages=flat)

    def on_llm_end(self, response: Any, **kwargs) -> None:
        try:
            generations = response.generations
            if generations and generations[0]:
                gen = generations[0][0]
                content = gen.text if hasattr(gen, "text") else str(gen)
                tool_calls = []
                if hasattr(gen, "message") and hasattr(gen.message, "tool_calls"):
                    tool_calls = [
                        {"name": tc.function.name, "args": tc.function.arguments}
                        for tc in (gen.message.tool_calls or [])
                    ]
                self._monitor.log_llm_response(content=content, tool_calls=tool_calls)
        except Exception:
            self._monitor.log_llm_response(content=str(response))

    def on_llm_error(self, error: Exception, **kwargs) -> None:
        pass  # Don't monitor errors — nothing to analyse

    # ── Tool callbacks ────────────────────────────────────────────────────────

    def on_tool_start(self, serialized: dict, input_str: str, **kwargs) -> None:
        tool_name = serialized.get("name", serialized.get("id", ["unknown"])[-1])
        self._current_tool = tool_name
        try:
            import json
            args = json.loads(input_str) if input_str.startswith("{") else {"input": input_str}
        except Exception:
            args = {"input": input_str}
        self._monitor.log_tool_call(tool=tool_name, args=args)

    def on_tool_end(self, output: str, **kwargs) -> None:
        tool_name = self._current_tool or "unknown"
        self._monitor.log_tool_result(tool=tool_name, result=output)
        self._current_tool = None

    def on_tool_error(self, error: Exception, **kwargs) -> None:
        self._monitor.log_tool_result(
            tool=self._current_tool or "unknown",
            result=None,
            error=str(error),
        )
        self._current_tool = None

    # ── Agent callbacks ───────────────────────────────────────────────────────

    def on_agent_action(self, action: Any, **kwargs) -> None:
        if hasattr(action, "tool") and hasattr(action, "tool_input"):
            inp = action.tool_input
            if isinstance(inp, str):
                try:
                    import json
                    inp = json.loads(inp)
                except Exception:
                    inp = {"input": inp}
            self._monitor.log_tool_call(tool=action.tool, args=inp)

    def on_agent_finish(self, finish: Any, **kwargs) -> None:
        pass

    # ── Retriever callbacks (RAG) ─────────────────────────────────────────────

    def on_retriever_start(self, serialized: dict, query: str, **kwargs) -> None:
        self._monitor.log_memory_read(query=query)

    def on_retriever_end(self, documents: list, **kwargs) -> None:
        results = [getattr(d, "page_content", str(d))[:200] for d in (documents or [])]
        self._monitor.log_memory_read(query="(retriever result)", results=results)

    # ── Monitor access ────────────────────────────────────────────────────────

    def flush(self) -> RuntimeAnalysisReport:
        return self._monitor.flush()

    @property
    def monitor(self) -> AgentScanMonitor:
        return self._monitor
