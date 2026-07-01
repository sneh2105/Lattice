# -*- coding: utf-8 -*-
"""
AgentScan Runtime Monitor
==========================
The core monitoring class. All framework integrations wrap this.

Three ways to use it:
  1. Direct API  -- call log_* methods explicitly
  2. Context manager (agentscan_trace) -- wraps a block of agent code
  3. Framework callbacks -- auto-wired via framework-specific classes

Output options:
  - Console alerts (immediate, for development)
  - JSONL file (for later analysis)
  - Webhook / HTTP POST (for SIEM integration)
  - In-memory (for testing)
"""

from __future__ import annotations
import agentscan._compat  # force UTF-8 on Windows

import json
import os
import sys
import time
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Generator

from agentscan.runtime.events import (
    AgentSession, RuntimeEvent, EventType,
    llm_request, llm_response, tool_call, tool_result,
    network_call, file_access, secret_access, process_spawn,
    memory_read, memory_write, db_query,
)
from agentscan.runtime.analyser import RuntimeAnalyser, RuntimeAnalysisReport
from agentscan.models import Severity


# ANSI for console output
_RED    = "\033[91m"
_ORANGE = "\033[33m"
_CYAN   = "\033[96m"
_GREEN  = "\033[92m"
_DIM    = "\033[2m"
_BOLD   = "\033[1m"
_RESET  = "\033[0m"


def _col(c: str, s: str) -> str:
    return f"{c}{s}{_RESET}" if sys.stdout.isatty() else s


@dataclass
class MonitorConfig:
    """Configuration for AgentScanMonitor."""
    agent_name: str = "agent"
    # Alert thresholds
    alert_on_injection: bool = True
    alert_on_exfil: bool = True
    alert_on_secret_exposure: bool = True
    alert_on_dangerous_commands: bool = True
    # Output destinations
    console_alerts: bool = True          # print alerts immediately
    jsonl_path: str | None = None        # write events to JSONL file
    report_path: str | None = None       # write final report to JSON
    webhook_url: str | None = None       # POST findings to webhook
    # Analysis
    analyse_on_flush: bool = True        # run full analysis on flush()
    stream_analysis: bool = True         # check each event as it arrives (fast path)
    # Session
    session_id: str | None = None       # auto-generated if None


class AgentScanMonitor:
    """
    Core runtime monitor. Attach to any agent framework.

    Thread-safe. Events are buffered in memory and flushed on demand
    or when the context manager exits.

    Example:
        monitor = AgentScanMonitor(MonitorConfig(agent_name="support-bot"))
        monitor.log_llm_request("gpt-4o", messages)
        monitor.log_tool_call("search", {"query": "..."})
        report = monitor.flush()
        if report.findings:
            print(f"[!] {len(report.findings)} security findings")
    """

    def __init__(self, config: MonitorConfig | None = None, agent_name: str = "agent"):
        if config is None:
            config = MonitorConfig(agent_name=agent_name)
        self.config = config
        self._session = AgentSession(
            session_id=config.session_id or str(uuid.uuid4())[:8],
            agent_id=config.agent_name,
        )
        self._lock = threading.Lock()
        self._analyser = RuntimeAnalyser()
        self._jsonl_handle = None
        self._finding_count = 0

        if config.jsonl_path:
            self._jsonl_handle = open(config.jsonl_path, "a", encoding="utf-8")

    # -- Logging API -----------------------------------------------------------

    def log_llm_request(self, model: str, messages: list[dict], **kwargs) -> RuntimeEvent:
        return self._log(llm_request(model, messages, **kwargs))

    def log_llm_response(self, content: str, model: str = "", tool_calls: list = None, **kwargs) -> RuntimeEvent:
        return self._log(llm_response(content, model, tool_calls or [], **kwargs))

    def log_tool_call(self, tool: str, args: dict = None, **kwargs) -> RuntimeEvent:
        return self._log(tool_call(tool, args or {}, **kwargs))

    def log_tool_result(self, tool: str, result: Any, error: str = None, **kwargs) -> RuntimeEvent:
        return self._log(tool_result(tool, result, error, **kwargs))

    def log_network_call(self, url: str, method: str = "GET", response_code: int = 200, **kwargs) -> RuntimeEvent:
        return self._log(network_call(url, method, response_code, **kwargs))

    def log_file_access(self, path: str, mode: str = "read", **kwargs) -> RuntimeEvent:
        return self._log(file_access(path, mode, **kwargs))

    def log_secret_access(self, name: str, source: str = "vault", **kwargs) -> RuntimeEvent:
        return self._log(secret_access(name, source, **kwargs))

    def log_process_spawn(self, command: str, **kwargs) -> RuntimeEvent:
        return self._log(process_spawn(command, **kwargs))

    def log_memory_read(self, query: str, results: list = None, **kwargs) -> RuntimeEvent:
        return self._log(memory_read(query, results or [], **kwargs))

    def log_db_query(self, query: str, table: str = "", **kwargs) -> RuntimeEvent:
        return self._log(db_query(query, table, **kwargs))

    # -- Internal --------------------------------------------------------------

    def _log(self, event: RuntimeEvent) -> RuntimeEvent:
        with self._lock:
            self._session.add_event(event)

        # Write to JSONL
        if self._jsonl_handle:
            line = json.dumps({
                "id": event.id,
                "type": event.type.value,
                "timestamp_ms": event.timestamp_ms,
                "data": event.data,
                "session_id": self._session.session_id,
                "agent_id": self._session.agent_id,
            })
            self._jsonl_handle.write(line + "\n")
            self._jsonl_handle.flush()

        # Stream analysis (fast path -- check single event for critical signals)
        if self.config.stream_analysis:
            self._stream_check(event)

        return event

    def _stream_check(self, event: RuntimeEvent) -> None:
        """Fast single-event checks for immediate alerting."""
        import re
        from agentscan.runtime.analyser import INJECTION_PATTERNS, SECRET_PATTERNS, DANGEROUS_COMMANDS, SUSPICIOUS_DOMAINS, json_flatten

        text = json_flatten(event.data)
        alerts = []

        if self.config.alert_on_injection and event.type in (
            EventType.LLM_REQUEST, EventType.TOOL_RESULT, EventType.MEMORY_READ
        ):
            for pattern, label, _ in INJECTION_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    alerts.append(("INJECTION", f"Prompt injection: {label}", Severity.CRITICAL))
                    break

        if self.config.alert_on_secret_exposure:
            for pattern, label in SECRET_PATTERNS:
                if re.search(pattern, text):
                    alerts.append(("SECRET", f"Credential in stream: {label}", Severity.CRITICAL))
                    break

        if self.config.alert_on_dangerous_commands and event.type in (
            EventType.TOOL_CALL, EventType.PROCESS_SPAWN
        ):
            for pattern, label in DANGEROUS_COMMANDS:
                if re.search(pattern, text, re.IGNORECASE):
                    alerts.append(("DANGEROUS_CMD", f"Dangerous command: {label}", Severity.CRITICAL))
                    break

        if self.config.alert_on_exfil and event.type == EventType.NETWORK_CALL:
            url = event.data.get("url", "")
            for domain in SUSPICIOUS_DOMAINS:
                if domain in url.lower():
                    alerts.append(("EXFIL", f"Suspicious network destination: {domain}", Severity.CRITICAL))
                    break

        for alert_type, message, sev in alerts:
            self._finding_count += 1
            if self.config.console_alerts:
                ts = event.timestamp_ms
                print(
                    f"\n{_col(_RED+_BOLD, '  [!] AgentScan ALERT')} "
                    f"[{_col(_RED, sev.value.upper())}] "
                    f"[{alert_type}] t+{ts}ms\n"
                    f"  {message}\n"
                    f"  Event: {event.summary()[:120]}\n",
                    file=sys.stderr,
                )
            if self.config.webhook_url:
                self._post_webhook(alert_type, message, sev, event)

    def _post_webhook(self, alert_type: str, message: str, sev: Severity, event: RuntimeEvent) -> None:
        try:
            import urllib.request
            payload = json.dumps({
                "source": "agentscan",
                "alert_type": alert_type,
                "severity": sev.value,
                "message": message,
                "session_id": self._session.session_id,
                "agent_id": self._session.agent_id,
                "event_type": event.type.value,
                "event_summary": event.summary(),
                "timestamp_ms": event.timestamp_ms,
            }).encode()
            req = urllib.request.Request(
                self.config.webhook_url,
                data=payload,
                headers={"Content-Type": "application/json", "User-Agent": "AgentScan/0.4"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=3)
        except Exception:
            pass  # Never block agent execution due to monitoring failure

    def flush(self) -> RuntimeAnalysisReport:
        """Run full analysis and return report. Call at end of session."""
        with self._lock:
            session_copy = self._session

        report = None
        if self.config.analyse_on_flush:
            report = self._analyser.analyse(session_copy)

            if self.config.console_alerts and report:
                n_crit = sum(1 for f in report.findings if f.severity == Severity.CRITICAL)
                if n_crit > 0:
                    print(
                        f"\n{_col(_RED+_BOLD, '  == AgentScan Session Report ==')}\n"
                        f"  Session : {session_copy.session_id}\n"
                        f"  Agent   : {session_copy.agent_id}\n"
                        f"  Events  : {len(session_copy.events)}\n"
                        f"  {_col(_RED, f'Critical findings: {n_crit}')}\n"
                        f"  {_col(_RED, f'Attack paths: {len(report.attack_paths)}')}\n",
                        file=sys.stderr,
                    )

            if self.config.report_path and report:
                _write_report(report, self.config.report_path)

        if self._jsonl_handle:
            self._jsonl_handle.close()

        return report

    @property
    def session_id(self) -> str:
        return self._session.session_id

    @property
    def event_count(self) -> int:
        return len(self._session.events)

    @property
    def live_findings(self) -> int:
        return self._finding_count


def _write_report(report: RuntimeAnalysisReport, path: str) -> None:
    data = {
        "session_id": report.session_id,
        "agent_id": report.agent_id,
        "event_count": report.event_count,
        "duration_ms": report.duration_ms,
        "critical_findings": sum(1 for f in report.findings if f.severity == Severity.CRITICAL),
        "attack_paths": len(report.attack_paths),
        "findings": [
            {"id": f.id, "title": f.title, "severity": f.severity.value,
             "explanation": f.explanation, "remediation": f.remediation}
            for f in report.findings
        ],
        "timeline": report.event_timeline,
        "anomalies": report.anomalies,
    }
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")


@contextmanager
def agentscan_trace(
    agent_name: str = "agent",
    console_alerts: bool = True,
    jsonl_path: str | None = None,
    report_path: str | None = None,
    webhook_url: str | None = None,
) -> Generator[AgentScanMonitor, None, None]:
    """
    Context manager for tracing an agent execution block.

    Usage:
        with agentscan_trace("my-agent", report_path="report.json") as monitor:
            result = my_agent.run(input)
            # monitor.log_* calls happen inside framework callbacks
        # report is written to report.json
    """
    config = MonitorConfig(
        agent_name=agent_name,
        console_alerts=console_alerts,
        jsonl_path=jsonl_path,
        report_path=report_path,
        webhook_url=webhook_url,
    )
    monitor = AgentScanMonitor(config)
    try:
        yield monitor
    finally:
        monitor.flush()
