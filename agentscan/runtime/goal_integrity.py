# -*- coding: utf-8 -*-
"""
Reasoning & Goal Integrity Analysis
======================================
Detects when an agent's reasoning or stated objectives drift from its
original goal due to prompt injection, poisoned memory, or untrusted context.

This is NOT pattern matching for injection strings (that's runtime/analyser.py).
This is semantic drift detection: did the agent's actual behaviour deviate
from what it was originally tasked to do, even without an obvious injection
string being present?

Three detection mechanisms:

1. GOAL DECLARATION TRACKING
   Extract the agent's stated goal from system prompt / first user message.
   Track every subsequent tool call and check: does this action serve the
   declared goal, or does it serve something else?

2. REASONING CHAIN CONSISTENCY
   If the agent exposes intermediate reasoning (chain-of-thought, ReAct
   "Thought:" steps), check whether each step logically follows from the
   previous one and from the stated goal -- flagging non-sequiturs that
   often indicate injected reasoning.

3. CAPABILITY-GOAL MISMATCH
   Check whether the tools/capabilities invoked are the kind a reasonable
   agent would need for the stated goal. A "summarise this document" goal
   that results in a shell_exec call is a structural red flag regardless
   of whether explicit injection text is found.
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Any

from agentscan.runtime.events import AgentSession, RuntimeEvent, EventType
from agentscan.models import Finding, Evidence, Severity, ConfidenceLevel


# Goal category -> expected tool categories (used for capability-goal mismatch detection)
GOAL_TOOL_EXPECTATIONS: dict[str, set[str]] = {
    "search":      {"search", "lookup", "query", "find", "retrieve", "knowledge"},
    "summarise":   {"read", "fetch", "get", "retrieve"},
    "summarize":   {"read", "fetch", "get", "retrieve"},
    "answer":      {"search", "lookup", "retrieve", "knowledge"},
    "translate":   set(),  # translation needs no tools at all
    "write":       {"write", "save", "create", "draft"},
    "schedule":    {"calendar", "schedule", "book", "appointment"},
    "support":     {"search", "knowledge", "ticket", "lookup"},
    "refund":      {"refund", "payment", "order", "lookup"},
    "weather":     {"weather", "forecast"},
}

# Tool categories that should NEVER appear for "read-only" / "informational" goals
ESCALATORY_TOOLS_FOR_LOW_RISK_GOALS = {
    "shell", "exec", "command", "subprocess", "delete", "drop", "truncate",
    "send_email", "transfer", "payment_send", "credential", "secret", "admin",
}

LOW_RISK_GOAL_KEYWORDS = {
    "search", "summarise", "summarize", "answer", "translate", "explain",
    "describe", "find information", "look up", "tell me about",
}


@dataclass
class GoalDeclaration:
    """The agent's extracted, declared goal."""
    raw_text: str
    category: str | None       # matched category from GOAL_TOOL_EXPECTATIONS
    is_low_risk: bool          # does this look like a read-only/informational task?
    source: str                # "system_prompt" | "first_user_message"


@dataclass
class DriftEvent:
    """A point where agent behaviour deviated from its declared goal."""
    event: RuntimeEvent
    drift_type: str            # "capability_mismatch" | "reasoning_nonsequitur" | "scope_expansion"
    explanation: str
    severity: Severity
    confidence: ConfidenceLevel


@dataclass
class GoalIntegrityReport:
    """Complete goal integrity analysis for a session."""
    declared_goal: GoalDeclaration | None
    drift_events: list[DriftEvent]
    tool_calls_analysed: int
    mismatched_tool_calls: int
    reasoning_steps_analysed: int
    nonsequitur_count: int
    findings: list[Finding]
    integrity_score: int        # 0-100, 100 = perfect goal adherence
    summary: str


def _extract_goal(session: AgentSession) -> GoalDeclaration | None:
    """Extract the agent's declared goal from system prompt or first user message."""
    for event in session.events:
        if event.type == EventType.LLM_REQUEST:
            messages = event.data.get("messages", [])
            sys_msgs = [m for m in messages if isinstance(m, dict) and m.get("role") == "system"]
            user_msgs = [m for m in messages if isinstance(m, dict) and m.get("role") == "user"]

            text, source = "", ""
            if sys_msgs:
                text, source = sys_msgs[0].get("content", ""), "system_prompt"
            elif user_msgs:
                text, source = user_msgs[0].get("content", ""), "first_user_message"

            if not text:
                continue

            text_lower = text.lower()
            category = None
            for cat in GOAL_TOOL_EXPECTATIONS:
                if cat in text_lower:
                    category = cat
                    break

            is_low_risk = any(kw in text_lower for kw in LOW_RISK_GOAL_KEYWORDS)

            return GoalDeclaration(raw_text=text[:300], category=category,
                                  is_low_risk=is_low_risk, source=source)
    return None


def _check_capability_goal_mismatch(
    goal: GoalDeclaration, session: AgentSession
) -> list[DriftEvent]:
    """Flag tool calls that don't match the declared goal's risk profile."""
    drift_events = []

    if not goal.is_low_risk:
        return drift_events  # only check this for declared low-risk goals

    for event in session.events:
        if event.type != EventType.TOOL_CALL:
            continue
        tool_name = str(event.data.get("tool", "")).lower()
        args_text = str(event.data.get("args", "")).lower()
        combined = tool_name + " " + args_text

        matched_escalatory = [kw for kw in ESCALATORY_TOOLS_FOR_LOW_RISK_GOALS if kw in combined]
        if matched_escalatory:
            drift_events.append(DriftEvent(
                event=event,
                drift_type="capability_mismatch",
                explanation=(
                    f"The agent's declared goal was low-risk/informational "
                    f"('{goal.raw_text[:80]}...'), but it invoked tool '{tool_name}' "
                    f"which matches escalatory capability keywords: {matched_escalatory}. "
                    "This is a structural mismatch between stated intent and actual action -- "
                    "a strong signal of goal hijacking even without an explicit injection string."
                ),
                severity=Severity.CRITICAL,
                confidence=ConfidenceLevel.MEDIUM,
            ))

    return drift_events


def _check_reasoning_consistency(session: AgentSession, goal: GoalDeclaration | None) -> list[DriftEvent]:
    """
    Check LLM response 'reasoning' content (if present) for non-sequiturs --
    sudden topic changes that don't follow from the conversation so far.
    """
    drift_events = []
    responses = [e for e in session.events if e.type == EventType.LLM_RESPONSE]

    # Simple heuristic: look for explicit reasoning markers that contradict the goal
    contradiction_patterns = [
        r"actually,?\s+(I should|let me|I'll|I will)\s+(instead|now)",
        r"(new|different|updated)\s+(instructions?|task|objective|goal)",
        r"disregard\s+(my|the)\s+(previous|original|stated)\s+(goal|task|purpose)",
        r"my\s+(real|true|actual)\s+(purpose|goal|task)\s+is",
    ]

    for event in responses:
        content = str(event.data.get("content", ""))
        for pattern in contradiction_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                drift_events.append(DriftEvent(
                    event=event,
                    drift_type="reasoning_nonsequitur",
                    explanation=(
                        f"The agent's response contains language suggesting a goal change "
                        f"mid-session: matched pattern '{pattern}'. This is consistent with "
                        "successful prompt injection that altered the agent's understanding "
                        "of its own objective."
                    ),
                    severity=Severity.HIGH,
                    confidence=ConfidenceLevel.MEDIUM,
                ))
    return drift_events


def _check_scope_expansion(session: AgentSession) -> list[DriftEvent]:
    """
    Detect scope expansion: the SET of distinct tools used grows
    unusually large relative to session length, suggesting the agent
    is being walked through an expanding attack surface.
    """
    drift_events = []
    tool_events = [e for e in session.events if e.type == EventType.TOOL_CALL]

    seen_tools: set[str] = set()
    for i, event in enumerate(tool_events):
        tool_name = str(event.data.get("tool", ""))
        is_new = tool_name not in seen_tools
        seen_tools.add(tool_name)

        # Flag if we're past the first 3 tool calls and STILL discovering new,
        # unrelated tool categories -- suggests goal creep
        if is_new and i >= 3 and len(seen_tools) > 4:
            drift_events.append(DriftEvent(
                event=event,
                drift_type="scope_expansion",
                explanation=(
                    f"By tool call #{i+1}, the agent has now used {len(seen_tools)} distinct "
                    f"tools ({sorted(seen_tools)}). This breadth of tool usage within a single "
                    "session is unusual and may indicate the agent's task scope has expanded "
                    "beyond its original goal, often via incremental injection."
                ),
                severity=Severity.MEDIUM,
                confidence=ConfidenceLevel.LOW,
            ))
            break  # only flag once per session

    return drift_events


def analyse_goal_integrity(session: AgentSession) -> GoalIntegrityReport:
    """
    Main entry point. Analyses a session for goal drift and reasoning integrity.
    """
    goal = _extract_goal(session)
    drift_events: list[DriftEvent] = []

    if goal:
        drift_events += _check_capability_goal_mismatch(goal, session)
    drift_events += _check_reasoning_consistency(session, goal)
    drift_events += _check_scope_expansion(session)

    tool_calls = [e for e in session.events if e.type == EventType.TOOL_CALL]
    responses = [e for e in session.events if e.type == EventType.LLM_RESPONSE]

    mismatched = sum(1 for d in drift_events if d.drift_type == "capability_mismatch")
    nonsequiturs = sum(1 for d in drift_events if d.drift_type == "reasoning_nonsequitur")

    # Integrity score: starts at 100, deducted per drift event by severity
    score = 100
    for d in drift_events:
        score -= {"CRITICAL": 35, "HIGH": 20, "MEDIUM": 10, "LOW": 5}.get(d.severity.value, 5)
    score = max(0, score)

    # Build findings
    findings: list[Finding] = []
    for i, d in enumerate(drift_events):
        findings.append(Finding(
            id=f"GOAL-DRIFT-{d.drift_type.upper()}-{i+1}",
            title=f"Goal integrity violation: {d.drift_type.replace('_', ' ')}",
            severity=d.severity,
            confidence=d.confidence,
            scanner="goal_integrity",
            explanation=d.explanation,
            impact=(
                "Agent behaviour has deviated from its declared goal -- this is the behavioural "
                "signature of successful prompt injection, memory poisoning, or context manipulation, "
                "even when no explicit injection pattern is present in the input text."
            ),
            remediation=(
                "Implement goal-binding: validate that each tool call serves the declared task "
                "before execution. Consider a 'goal guard' that re-confirms task scope with the "
                "user before invoking tools outside the expected capability set for the stated goal."
            ),
            evidence=[Evidence(
                source="goal_integrity_analysis",
                field=d.drift_type,
                observed_value=d.event.summary(),
                explanation=d.explanation[:150],
            )],
            mitre_atlas=["AML.T0051", "AML.T0054"],
            tags=["goal-integrity", d.drift_type],
        ))

    if goal:
        goal_summary = f"Declared goal ({goal.source}): {goal.raw_text[:100]}"
    else:
        goal_summary = "No declared goal extracted from session"

    summary = (
        f"{goal_summary}\n"
        f"Integrity score: {score}/100\n"
        f"Drift events: {len(drift_events)} "
        f"(capability mismatch: {mismatched}, reasoning non-sequitur: {nonsequiturs})"
    )

    return GoalIntegrityReport(
        declared_goal=goal,
        drift_events=drift_events,
        tool_calls_analysed=len(tool_calls),
        mismatched_tool_calls=mismatched,
        reasoning_steps_analysed=len(responses),
        nonsequitur_count=nonsequiturs,
        findings=findings,
        integrity_score=score,
        summary=summary,
    )
