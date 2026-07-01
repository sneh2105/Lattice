# -*- coding: utf-8 -*-
"""
Runtime Event Model
====================
Every observable action an AI agent takes becomes a typed Event.
Events are the raw material for the Runtime Attack Graph.

Event types map directly to what security teams actually want to see:
  LLM_REQUEST    -- what was sent to the model
  LLM_RESPONSE   -- what the model returned
  TOOL_CALL      -- which tool was invoked with which args
  TOOL_RESULT    -- what the tool returned
  DECISION       -- agent reasoning/decision logged
  NETWORK_CALL   -- outbound HTTP/socket call
  FILE_ACCESS    -- read/write to filesystem
  SECRET_ACCESS  -- credential or secret retrieval
  MEMORY_READ    -- agent reading from memory/vector store
  MEMORY_WRITE   -- agent writing to memory
  DB_QUERY       -- database query executed
  PROCESS_SPAWN  -- subprocess or shell command executed
  AGENT_START    -- agent session begins
  AGENT_END      -- agent session ends

Integration: agents emit events by calling agentscan.runtime.emit()
or by importing the SDK and wrapping LangChain/AutoGen callbacks.
"""

from __future__ import annotations
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EventType(str, Enum):
    LLM_REQUEST    = "llm_request"
    LLM_RESPONSE   = "llm_response"
    TOOL_CALL      = "tool_call"
    TOOL_RESULT    = "tool_result"
    DECISION       = "decision"
    NETWORK_CALL   = "network_call"
    FILE_ACCESS    = "file_access"
    SECRET_ACCESS  = "secret_access"
    MEMORY_READ    = "memory_read"
    MEMORY_WRITE   = "memory_write"
    DB_QUERY       = "db_query"
    PROCESS_SPAWN  = "process_spawn"
    AGENT_START    = "agent_start"
    AGENT_END      = "agent_end"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


@dataclass
class RuntimeEvent:
    """A single observable action taken by or involving an AI agent."""
    id: str                          = field(default_factory=lambda: str(uuid.uuid4())[:8])
    type: EventType                  = EventType.DECISION
    timestamp_ms: int                = field(default_factory=lambda: int(time.time() * 1000))
    session_id: str                  = ""
    agent_id: str                    = ""
    # Payload -- varies by event type
    data: dict[str, Any]             = field(default_factory=dict)
    # Security annotations (added by analyser, not by agent)
    risk_signals: list[str]          = field(default_factory=list)
    mitre_atlas: list[str]           = field(default_factory=list)

    def summary(self) -> str:
        """One-line summary for display."""
        d = self.data
        if self.type == EventType.TOOL_CALL:
            return f"tool_call({d.get('tool','?')}, args={str(d.get('args',{}))[:60]})"
        if self.type == EventType.LLM_REQUEST:
            prompt = str(d.get("messages", d.get("prompt", "")))[:80]
            return f"llm_request(model={d.get('model','?')}, prompt='{prompt}...')"
        if self.type == EventType.LLM_RESPONSE:
            return f"llm_response(content='{str(d.get('content',''))[:80]}...')"
        if self.type == EventType.NETWORK_CALL:
            return f"network({d.get('method','GET')} {d.get('url','?')})"
        if self.type == EventType.FILE_ACCESS:
            return f"file_{d.get('mode','read')}({d.get('path','?')})"
        if self.type == EventType.SECRET_ACCESS:
            return f"secret_access(name={d.get('name','?')})"
        if self.type == EventType.DB_QUERY:
            return f"db_query({str(d.get('query','?'))[:60]})"
        if self.type == EventType.PROCESS_SPAWN:
            return f"process_spawn(cmd={d.get('command','?')})"
        if self.type == EventType.MEMORY_READ:
            return f"memory_read(query={str(d.get('query','?'))[:60]})"
        return f"{self.type.value}({str(d)[:60]})"


@dataclass
class AgentSession:
    """A complete agent execution session -- ordered sequence of events."""
    session_id: str
    agent_id: str
    events: list[RuntimeEvent] = field(default_factory=list)
    metadata: dict[str, Any]   = field(default_factory=dict)

    def add_event(self, event: RuntimeEvent) -> None:
        event.session_id = self.session_id
        event.agent_id = self.agent_id
        self.events.append(event)

    def tool_calls(self) -> list[RuntimeEvent]:
        return [e for e in self.events if e.type == EventType.TOOL_CALL]

    def network_calls(self) -> list[RuntimeEvent]:
        return [e for e in self.events if e.type == EventType.NETWORK_CALL]

    def secret_accesses(self) -> list[RuntimeEvent]:
        return [e for e in self.events if e.type == EventType.SECRET_ACCESS]

    def llm_exchanges(self) -> list[tuple[RuntimeEvent, RuntimeEvent | None]]:
        """Pair LLM requests with their responses."""
        pairs = []
        events = [e for e in self.events if e.type in (EventType.LLM_REQUEST, EventType.LLM_RESPONSE)]
        i = 0
        while i < len(events):
            if events[i].type == EventType.LLM_REQUEST:
                resp = events[i+1] if i+1 < len(events) and events[i+1].type == EventType.LLM_RESPONSE else None
                pairs.append((events[i], resp))
                i += 2 if resp else 1
            else:
                i += 1
        return pairs


# -- Session builder helpers (for testing and integration) ---------------------

def make_event(type: EventType, **data) -> RuntimeEvent:
    return RuntimeEvent(type=type, data=data)

def llm_request(model: str, messages: list[dict], **kwargs) -> RuntimeEvent:
    return RuntimeEvent(type=EventType.LLM_REQUEST,
                       data={"model": model, "messages": messages, **kwargs})

def llm_response(content: str, model: str = "", tool_calls: list = None, **kwargs) -> RuntimeEvent:
    return RuntimeEvent(type=EventType.LLM_RESPONSE,
                       data={"content": content, "model": model,
                             "tool_calls": tool_calls or [], **kwargs})

def tool_call(tool: str, args: dict = None, **kwargs) -> RuntimeEvent:
    return RuntimeEvent(type=EventType.TOOL_CALL,
                       data={"tool": tool, "args": args or {}, **kwargs})

def tool_result(tool: str, result: Any, error: str = None, **kwargs) -> RuntimeEvent:
    return RuntimeEvent(type=EventType.TOOL_RESULT,
                       data={"tool": tool, "result": result, "error": error, **kwargs})

def network_call(url: str, method: str = "GET", response_code: int = 200, **kwargs) -> RuntimeEvent:
    return RuntimeEvent(type=EventType.NETWORK_CALL,
                       data={"url": url, "method": method, "response_code": response_code, **kwargs})

def file_access(path: str, mode: str = "read", **kwargs) -> RuntimeEvent:
    return RuntimeEvent(type=EventType.FILE_ACCESS,
                       data={"path": path, "mode": mode, **kwargs})

def secret_access(name: str, source: str = "vault", **kwargs) -> RuntimeEvent:
    return RuntimeEvent(type=EventType.SECRET_ACCESS,
                       data={"name": name, "source": source, **kwargs})

def process_spawn(command: str, **kwargs) -> RuntimeEvent:
    return RuntimeEvent(type=EventType.PROCESS_SPAWN,
                       data={"command": command, **kwargs})

def memory_read(query: str, results: list = None, **kwargs) -> RuntimeEvent:
    return RuntimeEvent(type=EventType.MEMORY_READ,
                       data={"query": query, "results": results or [], **kwargs})

def db_query(query: str, table: str = "", **kwargs) -> RuntimeEvent:
    return RuntimeEvent(type=EventType.DB_QUERY,
                       data={"query": query, "table": table, **kwargs})

def memory_write(content: str, key: str = "", **kwargs) -> RuntimeEvent:
    return RuntimeEvent(type=EventType.MEMORY_WRITE,
                       data={"content": content, "key": key, **kwargs})
