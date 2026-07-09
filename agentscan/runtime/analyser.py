# -*- coding: utf-8 -*-
"""
Runtime Attack Graph Analyser
==============================
Converts a sequence of runtime events into a Runtime Attack Graph --
showing what the agent actually did, not just what it could do.

This answers: "What did the AI actually do?"

Output:
  - Ordered event chain (timeline)
  - Runtime attack paths (actual sequences leading to sensitive actions)
  - Anomaly detection (actions that deviate from expected patterns)
  - MITRE ATLAS annotation per event
  - "What actually happened" narrative
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Any

from agentscan.runtime.events import (
    AgentSession, RuntimeEvent, EventType,
)
from agentscan.models import Finding, Evidence, Severity, ConfidenceLevel


# -- Detection rules -----------------------------------------------------------

# Prompt injection signals in LLM input
INJECTION_PATTERNS = [
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", "Classic ignore-previous pattern", "AML.T0051"),
    (r"you\s+are\s+now\s+(a\s+)?(?!helpful|an?\s+AI)", "Persona override attempt", "AML.T0051"),
    (r"disregard\s+(your\s+)?(previous|system|all)", "Disregard instruction pattern", "AML.T0051"),
    (r"\[jailbreak\]|\[DAN\]|do\s+anything\s+now", "Known jailbreak token", "AML.T0051"),
    (r"<\|im_start\|>|<\|im_end\|>|<\|system\|>", "Chat template injection", "AML.T0051"),
    (r"SYSTEM:\s*you\s+are", "Inline system prompt injection", "AML.T0051"),
]

# Credential / secret patterns in any content
SECRET_PATTERNS = [
    (r"(AKIA|ASIA)[A-Z0-9]{16}", "AWS Access Key ID"),
    (r"sk-[A-Za-z0-9]{32,}", "OpenAI-style API key"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub personal access token"),
    (r"eyJ[A-Za-z0-9+/]{20,}={0,2}", "JWT token"),
    (r"-----BEGIN (RSA |EC )?PRIVATE KEY-----", "Private key material"),
    (r"(password|passwd|pwd|secret)\s*[=:]\s*['\"]?[^\s'\"]{8,}", "Hardcoded password"),
]

# Suspicious network destinations
SUSPICIOUS_DOMAINS = [
    "requestbin", "webhook.site", "ngrok.io", "burpcollaborator",
    "canary.tools", "canarytokens", "pipedream.net", "beeceptor",
]

# Dangerous shell command patterns
DANGEROUS_COMMANDS = [
    (r"curl\s+.*\s+-[oO]\s+", "curl with output redirect -- potential dropper"),
    (r"wget\s+.*\s+-[oO]\s+", "wget with output -- potential dropper"),
    (r"base64\s+--decode|base64\s+-d\b", "base64 decode -- obfuscation pattern"),
    (r"\|\s*(bash|sh|python|perl|ruby)\b", "Pipe to interpreter -- RCE pattern"),
    (r"chmod\s+[+u]x\b", "chmod +x -- making file executable"),
    (r"cron(tab)?\s+-[el]", "Crontab modification -- persistence"),
    (r"(nc|ncat|netcat)\s+.*-[el]\s+", "Netcat listener/reverse shell"),
    (r"/etc/(passwd|shadow|sudoers)", "Reading sensitive system files"),
    (r"(aws|gcloud|az)\s+.*credentials", "Cloud credential CLI access"),
    (r"env\s*\|?\s*grep\s+.*(KEY|SECRET|TOKEN|PASSWORD)", "Env var credential grep"),
]


@dataclass
class RuntimeFinding:
    """A finding from runtime analysis -- tied to specific events."""
    id: str
    title: str
    severity: Severity
    confidence: ConfidenceLevel
    explanation: str
    impact: str
    remediation: str
    events: list[RuntimeEvent]     # the events that triggered this finding
    mitre_atlas: list[str]
    tags: list[str] = field(default_factory=list)

    def to_finding(self) -> Finding:
        return Finding(
            id=self.id, title=self.title,
            severity=self.severity, confidence=self.confidence,
            scanner="runtime_analyser",
            explanation=self.explanation, impact=self.impact,
            remediation=self.remediation,
            evidence=[Evidence(
                source="runtime_event",
                field=e.type.value,
                observed_value=e.summary(),
                explanation=f"Event at t+{e.timestamp_ms}ms"
            ) for e in self.events[:3]],
            mitre_atlas=self.mitre_atlas,
            tags=self.tags,
        )


@dataclass
class RuntimeAttackPath:
    """An actual observed sequence leading to a sensitive action."""
    title: str
    severity: Severity
    events: list[RuntimeEvent]
    entry_event: RuntimeEvent
    terminal_event: RuntimeEvent
    description: str
    mitre_atlas: list[str]
    composite_score: float


@dataclass
class RuntimeAnalysisReport:
    """Complete runtime analysis of an agent session."""
    session_id: str
    agent_id: str
    event_count: int
    duration_ms: int
    findings: list[RuntimeFinding]
    attack_paths: list[RuntimeAttackPath]
    event_timeline: list[dict]        # human-readable timeline
    anomalies: list[str]
    summary: str


class RuntimeAnalyser:
    """
    Analyses an AgentSession and produces a RuntimeAnalysisReport.

    Usage:
        session = AgentSession(session_id="s1", agent_id="support-bot")
        session.add_event(llm_request(...))
        session.add_event(tool_call("shell_exec", args={"cmd": "env | grep AWS"}))
        ...
        report = RuntimeAnalyser().analyse(session)
    """

    def analyse(self, session: AgentSession) -> RuntimeAnalysisReport:
        findings: list[RuntimeFinding] = []
        attack_paths: list[RuntimeAttackPath] = []
        anomalies: list[str] = []

        # Run all detection passes
        findings += self._detect_prompt_injection(session)
        findings += self._detect_secret_exposure(session)
        findings += self._detect_credential_exfil_chain(session)
        findings += self._detect_dangerous_commands(session)
        findings += self._detect_suspicious_network(session)
        findings += self._detect_secret_to_network_chain(session)
        findings += self._detect_tool_result_injection(session)

        # Build runtime attack paths from event sequences
        attack_paths = self._build_runtime_paths(session, findings)

        # Build human-readable timeline
        timeline = self._build_timeline(session)

        # Anomaly detection
        anomalies = self._detect_anomalies(session)

        # Duration
        if session.events:
            duration = session.events[-1].timestamp_ms - session.events[0].timestamp_ms
        else:
            duration = 0

        # Summary
        summary = self._build_summary(session, findings, attack_paths)

        return RuntimeAnalysisReport(
            session_id=session.session_id,
            agent_id=session.agent_id,
            event_count=len(session.events),
            duration_ms=duration,
            findings=findings,
            attack_paths=attack_paths,
            event_timeline=timeline,
            anomalies=anomalies,
            summary=summary,
        )

    # -- Detection passes ------------------------------------------------------

    def _detect_prompt_injection(self, session: AgentSession) -> list[RuntimeFinding]:
        findings = []
        for event in session.events:
            if event.type not in (EventType.LLM_REQUEST, EventType.TOOL_RESULT, EventType.MEMORY_READ):
                continue
            text = json_flatten(event.data)
            for pattern, label, mitre in INJECTION_PATTERNS:
                m = re.search(pattern, text, re.IGNORECASE)
                if m:
                    source = "user input" if event.type == EventType.LLM_REQUEST else \
                             "tool result" if event.type == EventType.TOOL_RESULT else "memory"
                    findings.append(RuntimeFinding(
                        id=f"RT-INJECT-{label[:15].upper().replace(' ','-')}",
                        title=f"Prompt injection pattern in {source}: '{label}'",
                        severity=Severity.CRITICAL,
                        confidence=ConfidenceLevel.HIGH,
                        explanation=(
                            f"The agent received text containing a '{label}' prompt injection pattern "
                            f"via {source}. This may cause the agent to deviate from its intended behaviour, "
                            "override safety policies, or execute unintended tool calls."
                        ),
                        impact="Agent may follow attacker instructions instead of system prompt -- tool abuse, data exfil, policy bypass.",
                        remediation="Add input/output guardrails that detect and block injection patterns. "
                                    "Treat all external content (tool results, retrieved documents) as untrusted.",
                        events=[event],
                        mitre_atlas=[mitre, "AML.T0054"],
                        tags=["runtime", "prompt-injection", source.replace(" ","-")],
                    ))
        return findings

    def _detect_secret_exposure(self, session: AgentSession) -> list[RuntimeFinding]:
        findings = []
        for event in session.events:
            text = json_flatten(event.data)
            for pattern, label in SECRET_PATTERNS:
                if re.search(pattern, text):
                    findings.append(RuntimeFinding(
                        id=f"RT-SECRET-{label[:15].upper().replace(' ','-')}",
                        title=f"Credential/secret in agent data stream: {label}",
                        severity=Severity.CRITICAL,
                        confidence=ConfidenceLevel.HIGH,
                        explanation=(
                            f"A '{label}' was detected in agent event data ({event.type.value}). "
                            "Credentials in the agent's data stream can be logged, injected into "
                            "LLM context, or exfiltrated via tool calls."
                        ),
                        impact="Credential exposure -- may appear in LLM logs, audit trails, or be exfiltrated.",
                        remediation="Never pass raw credentials through the agent data stream. "
                                    "Use secret injection at runtime -- not via tool results or prompts.",
                        events=[event],
                        mitre_atlas=["AML.T0051"],
                        tags=["runtime", "credential-exposure"],
                    ))
        return findings

    def _detect_dangerous_commands(self, session: AgentSession) -> list[RuntimeFinding]:
        findings = []
        for event in session.events:
            if event.type not in (EventType.TOOL_CALL, EventType.PROCESS_SPAWN):
                continue
            cmd = str(event.data.get("command", event.data.get("args", {}).get("command",
                      event.data.get("args", {}).get("cmd", ""))))
            for pattern, label in DANGEROUS_COMMANDS:
                if re.search(pattern, cmd, re.IGNORECASE):
                    findings.append(RuntimeFinding(
                        id=f"RT-CMD-{label[:15].upper().replace(' ','-').replace('--','')}",
                        title=f"Dangerous command pattern observed at runtime: '{label}'",
                        severity=Severity.CRITICAL,
                        confidence=ConfidenceLevel.HIGH,
                        explanation=(
                            f"The agent executed a command matching '{label}'. "
                            f"Command: `{cmd[:120]}`. "
                            "This is consistent with exploitation, persistence, or exfiltration activity."
                        ),
                        impact="Host compromise, credential theft, persistence, or data exfiltration.",
                        remediation="Implement command allowlisting. Alert on and block pattern matches. "
                                    "Review why the agent issued this command.",
                        events=[event],
                        mitre_atlas=["AML.T0017", "AML.T0048"],
                        tags=["runtime", "dangerous-command", "process"],
                    ))
        return findings

    def _detect_suspicious_network(self, session: AgentSession) -> list[RuntimeFinding]:
        findings = []
        for event in session.events:
            if event.type != EventType.NETWORK_CALL:
                continue
            url = event.data.get("url", "")
            for domain in SUSPICIOUS_DOMAINS:
                if domain in url.lower():
                    findings.append(RuntimeFinding(
                        id=f"RT-NET-SUSPICIOUS-{domain[:10].upper()}",
                        title=f"Network call to suspicious/interception domain: {domain}",
                        severity=Severity.CRITICAL,
                        confidence=ConfidenceLevel.HIGH,
                        explanation=(
                            f"The agent made an HTTP call to '{url}', which contains '{domain}' -- "
                            "a domain associated with request inspection/interception tools. "
                            "This is a strong signal of active data exfiltration."
                        ),
                        impact="Data exfiltration to attacker-controlled infrastructure.",
                        remediation="Block this network call immediately. Review what data was sent. "
                                    "Implement network egress allowlisting.",
                        events=[event],
                        mitre_atlas=["AML.T0040"],
                        tags=["runtime", "network", "exfiltration"],
                    ))
        return findings

    def _detect_credential_exfil_chain(self, session: AgentSession) -> list[RuntimeFinding]:
        """Detect: secret access -> network call (within same session)."""
        findings = []
        secret_events = [e for e in session.events if e.type == EventType.SECRET_ACCESS]
        network_events = [e for e in session.events if e.type == EventType.NETWORK_CALL]
        if secret_events and network_events:
            # Check if network call comes after a secret access
            for se in secret_events:
                later_net = [ne for ne in network_events if ne.timestamp_ms >= se.timestamp_ms]
                if later_net:
                    findings.append(RuntimeFinding(
                        id="RT-CHAIN-CRED-EXFIL",
                        title="RUNTIME: Credential access followed by network call -- exfiltration chain",
                        severity=Severity.CRITICAL,
                        confidence=ConfidenceLevel.HIGH,
                        explanation=(
                            f"The agent accessed secret '{se.data.get('name','?')}' and "
                            f"subsequently made a network call to '{later_net[0].data.get('url','?')}'. "
                            "This is the runtime manifestation of a credential exfiltration attack."
                        ),
                        impact="Live credential exfiltration -- attacker may have received the secret.",
                        remediation="Immediately rotate the exposed credential. Review network logs. "
                                    "Add a control requiring human approval before any network call "
                                    "following a secret retrieval.",
                        events=[se, later_net[0]],
                        mitre_atlas=["AML.T0051", "AML.T0040"],
                        tags=["runtime", "attack-chain", "exfiltration"],
                    ))
        return findings

    def _detect_secret_to_network_chain(self, session: AgentSession) -> list[RuntimeFinding]:
        """Detect secrets in tool results that are then sent in network calls."""
        findings = []
        for i, event in enumerate(session.events):
            if event.type != EventType.TOOL_RESULT:
                continue
            result_text = json_flatten(event.data)
            for pattern, label in SECRET_PATTERNS:
                if re.search(pattern, result_text):
                    # Look for subsequent network call
                    later = [e for e in session.events[i+1:] if e.type == EventType.NETWORK_CALL]
                    if later:
                        findings.append(RuntimeFinding(
                            id=f"RT-CHAIN-TOOLSECRET-NET-{label[:10].upper().replace(' ','-')}",
                            title=f"Secret in tool result -> network call: '{label}' pattern",
                            severity=Severity.CRITICAL,
                            confidence=ConfidenceLevel.MEDIUM,
                            explanation=(
                                f"A tool returned data containing a '{label}' pattern. "
                                f"Subsequently the agent made a network call to "
                                f"'{later[0].data.get('url','?')}'. The credential may have been exfiltrated."
                            ),
                            impact="Credential in tool result may have been exfiltrated via network call.",
                            remediation="Redact secrets from tool results before they reach the agent context. "
                                        "Use secret references (not values) in tool responses.",
                            events=[event, later[0]],
                            mitre_atlas=["AML.T0051", "AML.T0040"],
                            tags=["runtime", "attack-chain", "tool-result"],
                        ))
        return findings

    def _detect_tool_result_injection(self, session: AgentSession) -> list[RuntimeFinding]:
        """Detect prompt injection arriving via tool results (indirect injection)."""
        findings = []
        for event in session.events:
            if event.type != EventType.TOOL_RESULT:
                continue
            text = json_flatten(event.data)
            for pattern, label, mitre in INJECTION_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    # Check if a subsequent tool call happens (injection succeeded?)
                    idx = session.events.index(event)
                    later_tools = [e for e in session.events[idx+1:] if e.type == EventType.TOOL_CALL]
                    if later_tools:
                        findings.append(RuntimeFinding(
                            id=f"RT-INDIRECT-INJECT-{label[:12].upper().replace(' ','-')}",
                            title="Indirect prompt injection via tool result -> subsequent tool call",
                            severity=Severity.CRITICAL,
                            confidence=ConfidenceLevel.HIGH,
                            explanation=(
                                f"A tool result contained '{label}' (injection pattern). "
                                f"This was followed by a tool call to '{later_tools[0].data.get('tool','?')}'. "
                                "This is the classic indirect prompt injection attack -- attacker-controlled "
                                "data (web page, DB row, email) overrides the agent's instructions."
                            ),
                            impact="Agent executed attacker-injected instructions via tool result content.",
                            remediation="Treat all tool results as untrusted. Apply output guardrails before "
                                        "tool results are fed back into the LLM context.",
                            events=[event, later_tools[0]],
                            mitre_atlas=["AML.T0051", "AML.T0054"],
                            tags=["runtime", "indirect-injection", "tool-result"],
                        ))
        return findings

    # -- Runtime attack path construction -------------------------------------

    def _build_runtime_paths(
        self, session: AgentSession, findings: list[RuntimeFinding]
    ) -> list[RuntimeAttackPath]:
        paths = []

        # Path: injection -> tool call
        inject_findings = [f for f in findings if "injection" in " ".join(f.tags)]
        tool_findings = [f for f in findings if "process" in " ".join(f.tags) or "command" in " ".join(f.tags)]

        if inject_findings and tool_findings:
            entry = inject_findings[0].events[0]
            terminal = tool_findings[0].events[0]
            chain = self._events_between(session, entry, terminal)
            paths.append(RuntimeAttackPath(
                title="Runtime: Prompt injection -> dangerous command execution",
                severity=Severity.CRITICAL,
                events=chain,
                entry_event=entry,
                terminal_event=terminal,
                description=(
                    "An injection pattern was detected in agent input, and the agent subsequently "
                    "executed a dangerous command. This indicates a successful prompt injection attack "
                    "that resulted in unintended command execution."
                ),
                mitre_atlas=["AML.T0051", "AML.T0017"],
                composite_score=95.0,
            ))

        # Path: secret access -> network exfiltration
        exfil_findings = [f for f in findings if "exfiltration" in " ".join(f.tags) or "CRED-EXFIL" in f.id]
        if exfil_findings:
            ef = exfil_findings[0]
            if len(ef.events) >= 2:
                chain = self._events_between(session, ef.events[0], ef.events[-1])
                paths.append(RuntimeAttackPath(
                    title="Runtime: Credential accessed and sent to external network",
                    severity=Severity.CRITICAL,
                    events=chain,
                    entry_event=ef.events[0],
                    terminal_event=ef.events[-1],
                    description=(
                        "The agent retrieved a secret/credential and subsequently made an outbound "
                        "network call. This is a live credential exfiltration event."
                    ),
                    mitre_atlas=["AML.T0051", "AML.T0040"],
                    composite_score=92.0,
                ))

        return sorted(paths, key=lambda p: -p.composite_score)

    def _events_between(self, session: AgentSession, start: RuntimeEvent, end: RuntimeEvent) -> list[RuntimeEvent]:
        """Return all events from start to end inclusive."""
        events = session.events
        try:
            i = events.index(start)
            j = events.index(end)
            return events[i:j+1]
        except ValueError:
            return [start, end]

    # -- Timeline --------------------------------------------------------------

    def _build_timeline(self, session: AgentSession) -> list[dict]:
        if not session.events:
            return []
        t0 = session.events[0].timestamp_ms
        timeline = []
        for event in session.events:
            entry = {
                "t_ms": event.timestamp_ms - t0,
                "type": event.type.value,
                "summary": event.summary(),
                "risk_signals": event.risk_signals,
            }
            timeline.append(entry)
        return timeline

    def _detect_anomalies(self, session: AgentSession) -> list[str]:
        anomalies = []
        tool_calls = session.tool_calls()
        net_calls = session.network_calls()
        secret_events = session.secret_accesses()

        if len(tool_calls) > 20:
            anomalies.append(f"Unusually high tool call count: {len(tool_calls)} (possible runaway agent)")
        if len(net_calls) > 10:
            anomalies.append(f"High network call volume: {len(net_calls)} outbound requests")
        if len(secret_events) > 3:
            anomalies.append(f"Multiple secret accesses: {len(secret_events)} retrievals in one session")

        # Rapid-fire tool calls (< 100ms apart) = possible loop
        for i in range(1, len(tool_calls)):
            if tool_calls[i].timestamp_ms - tool_calls[i-1].timestamp_ms < 100:
                anomalies.append("Rapid-fire tool calls detected (< 100ms apart) -- possible agent loop")
                break

        return anomalies

    def _build_summary(self, session: AgentSession,
                       findings: list[RuntimeFinding],
                       paths: list[RuntimeAttackPath]) -> str:
        crit = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        tools_called = {e.data.get("tool", "?") for e in session.tool_calls()}
        nets = {e.data.get("url","?") for e in session.network_calls()}

        lines = [
            f"Session {session.session_id} | Agent: {session.agent_id}",
            f"Events: {len(session.events)}  |  Critical findings: {crit}  |  Attack paths: {len(paths)}",
        ]
        if tools_called:
            lines.append(f"Tools invoked: {', '.join(sorted(tools_called))}")
        if nets:
            lines.append(f"Network calls: {', '.join(list(nets)[:3])}")
        if paths:
            lines.append(f"[!] CRITICAL: {paths[0].title}")
        return "\n".join(lines)


def json_flatten(data: Any) -> str:
    """Flatten any data structure to a searchable string."""
    if isinstance(data, str):
        return data
    try:
        import json
        return json.dumps(data, default=str)
    except Exception:
        return str(data)
