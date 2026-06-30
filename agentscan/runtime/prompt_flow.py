"""
Prompt Flow Analyser
====================
Models the complete prompt data flow through an agent:

  User → System Prompt → Memory → RAG → Tool → LLM → Response

Answers:
  1. Can prompt injection reach tools?
  2. Can jailbreaks bypass policies?
  3. Is the system prompt exposing secrets?
  4. Can retrieved documents override instructions?
  5. What data actually reaches the LLM context?
  6. Where do tool results feed back in?
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Any

from agentscan.runtime.events import AgentSession, RuntimeEvent, EventType
from agentscan.runtime.analyser import INJECTION_PATTERNS, SECRET_PATTERNS, json_flatten
from agentscan.models import Finding, Evidence, Severity, ConfidenceLevel


@dataclass
class FlowNode:
    """A stage in the prompt data flow."""
    id: str
    label: str
    stage: str         # "input" | "context" | "processing" | "output"
    data_sample: str   # what data flows through this node (truncated)
    risk_level: str    # "safe" | "low" | "medium" | "high" | "critical"
    findings: list[str] = field(default_factory=list)


@dataclass
class FlowEdge:
    """Data flowing from one stage to another."""
    src: str
    dst: str
    label: str
    carries_attacker_data: bool = False
    carries_secrets: bool = False


@dataclass
class PromptFlowReport:
    """Complete prompt flow analysis."""
    nodes: list[FlowNode]
    edges: list[FlowEdge]
    findings: list[Finding]
    injection_reach: list[str]    # which stages are reachable by injection
    secret_exposure: list[str]    # where secrets appear in the flow
    policy_bypass_risk: bool
    rag_override_risk: bool
    summary: str


class PromptFlowAnalyser:
    """
    Analyses the data flow through a prompt/agent execution.

    Can operate in two modes:
    1. Static — given a system prompt, tools, RAG config
    2. Runtime — given an AgentSession with actual events
    """

    def analyse_session(self, session: AgentSession) -> PromptFlowReport:
        """Build prompt flow from runtime events."""
        nodes: list[FlowNode] = []
        edges: list[FlowEdge] = []
        findings: list[Finding] = []
        injection_reach: list[str] = []
        secret_locations: list[str] = []

        # Extract components from session events
        llm_requests = [e for e in session.events if e.type == EventType.LLM_REQUEST]
        llm_responses = [e for e in session.events if e.type == EventType.LLM_RESPONSE]
        tool_calls = [e for e in session.events if e.type == EventType.TOOL_CALL]
        tool_results = [e for e in session.events if e.type == EventType.TOOL_RESULT]
        memory_reads = [e for e in session.events if e.type == EventType.MEMORY_READ]

        # ── Build flow nodes ──────────────────────────────────────────────────

        # User input node
        user_msgs = []
        for req in llm_requests:
            msgs = req.data.get("messages", [])
            user_msgs += [m for m in msgs if isinstance(m, dict) and m.get("role") == "user"]
        user_text = " ".join(m.get("content","") for m in user_msgs)
        user_risk, user_findings = self._check_injection(user_text, "user input")
        if user_findings: injection_reach.append("user_input")
        nodes.append(FlowNode(
            id="user_input", label="User Input", stage="input",
            data_sample=user_text[:200], risk_level=user_risk,
            findings=user_findings,
        ))

        # System prompt node
        sys_msgs = []
        for req in llm_requests[:1]:
            msgs = req.data.get("messages", [])
            sys_msgs += [m for m in msgs if isinstance(m, dict) and m.get("role") == "system"]
        sys_text = " ".join(m.get("content","") for m in sys_msgs)
        sys_risk = "safe"
        sys_findings_list = []
        if sys_text:
            _, sys_findings_list = self._check_injection(sys_text, "system prompt")
            secret_in_sys = self._check_secrets(sys_text)
            if secret_in_sys:
                secret_locations.append("system_prompt")
                sys_risk = "critical"
                sys_findings_list.append("Credentials detected in system prompt")
        nodes.append(FlowNode(
            id="system_prompt", label="System Prompt", stage="context",
            data_sample=sys_text[:200] if sys_text else "(not captured)",
            risk_level=sys_risk, findings=sys_findings_list,
        ))

        # Memory / RAG node
        mem_data = ""
        if memory_reads:
            mem_data = json_flatten(memory_reads[0].data)[:300]
        mem_risk, mem_findings_list = self._check_injection(mem_data, "memory/RAG") if mem_data else ("safe", [])
        if mem_findings_list: injection_reach.append("memory_rag")
        nodes.append(FlowNode(
            id="memory_rag", label="Memory / RAG Context", stage="context",
            data_sample=mem_data[:200], risk_level=mem_risk,
            findings=mem_findings_list,
        ))

        # LLM processing node
        nodes.append(FlowNode(
            id="llm", label="LLM", stage="processing",
            data_sample=f"{len(llm_requests)} request(s), {len(llm_responses)} response(s)",
            risk_level="safe" if not injection_reach else "high",
            findings=([f"Receives tainted data from: {', '.join(injection_reach)}"] if injection_reach else []),
        ))

        # Tool nodes
        for tc in tool_calls[:3]:
            tool_name = tc.data.get("tool","?")
            args_text = json_flatten(tc.data.get("args", {}))
            t_risk, t_findings = self._check_injection(args_text, f"tool '{tool_name}' args")
            if t_findings: injection_reach.append(f"tool_{tool_name}")
            nodes.append(FlowNode(
                id=f"tool_{tool_name}", label=f"Tool: {tool_name}", stage="processing",
                data_sample=args_text[:200], risk_level=t_risk,
                findings=t_findings,
            ))

        # Tool results → back to LLM
        for tr in tool_results[:3]:
            tool_name = tr.data.get("tool","?")
            result_text = json_flatten(tr.data.get("result",""))
            tr_risk, tr_findings = self._check_injection(result_text, f"tool result '{tool_name}'")
            sec = self._check_secrets(result_text)
            if sec: secret_locations.append(f"tool_result_{tool_name}")
            if tr_findings: injection_reach.append(f"tool_result_{tool_name}")
            nodes.append(FlowNode(
                id=f"tool_result_{tool_name}", label=f"Tool Result: {tool_name}", stage="context",
                data_sample=result_text[:200], risk_level="critical" if tr_risk=="critical" or sec else tr_risk,
                findings=tr_findings + (["Secret pattern in tool result"] if sec else []),
            ))

        # Response node
        resp_text = " ".join(str(r.data.get("content","")) for r in llm_responses)
        resp_risk, resp_findings_list = "safe", []
        if self._check_secrets(resp_text):
            resp_risk = "critical"
            secret_locations.append("llm_response")
            resp_findings_list.append("Secret pattern in LLM response — credential leak in output")
        nodes.append(FlowNode(
            id="response", label="LLM Response", stage="output",
            data_sample=resp_text[:200], risk_level=resp_risk,
            findings=resp_findings_list,
        ))

        # ── Build flow edges ──────────────────────────────────────────────────
        edges = [
            FlowEdge("user_input",    "llm",        "user message",
                     carries_attacker_data="user_input" in injection_reach),
            FlowEdge("system_prompt", "llm",        "context",
                     carries_secrets="system_prompt" in secret_locations),
            FlowEdge("memory_rag",    "llm",        "retrieved context",
                     carries_attacker_data="memory_rag" in injection_reach),
        ]
        for tc in tool_calls[:3]:
            name = tc.data.get("tool","?")
            edges.append(FlowEdge("llm", f"tool_{name}", "tool invocation",
                                  carries_attacker_data=f"tool_{name}" in injection_reach))
            edges.append(FlowEdge(f"tool_{name}", f"tool_result_{name}", "execution",
                                  carries_attacker_data=False))
            edges.append(FlowEdge(f"tool_result_{name}", "llm", "result context",
                                  carries_attacker_data=f"tool_result_{name}" in injection_reach,
                                  carries_secrets=f"tool_result_{name}" in secret_locations))
        edges.append(FlowEdge("llm", "response", "generation",
                               carries_secrets="llm_response" in secret_locations))

        # ── Findings ──────────────────────────────────────────────────────────
        if injection_reach:
            findings.append(Finding(
                id="PF-INJECT-REACHABLE",
                title=f"Prompt injection can reach {len(injection_reach)} flow stage(s)",
                severity=Severity.CRITICAL, confidence=ConfidenceLevel.HIGH,
                scanner="prompt_flow",
                explanation=(
                    f"Attacker-controlled content can reach the following stages: "
                    f"{', '.join(injection_reach)}. "
                    "Any of these stages can propagate injected instructions to the LLM or tools."
                ),
                impact="Full prompt injection attack surface — attacker can override instructions, "
                       "call arbitrary tools, or exfiltrate data.",
                remediation="Apply input validation at every trust boundary. Treat tool results and "
                             "RAG context as untrusted. Use structured output parsing rather than "
                             "free-text LLM responses to drive tool calls.",
                evidence=[Evidence("prompt_flow", "injection_reach", injection_reach,
                                   f"{len(injection_reach)} stages carry potentially-injected data")],
                mitre_atlas=["AML.T0051", "AML.T0054"],
            ))

        if secret_locations:
            findings.append(Finding(
                id="PF-SECRET-IN-FLOW",
                title=f"Secrets detected at {len(secret_locations)} point(s) in prompt flow",
                severity=Severity.CRITICAL, confidence=ConfidenceLevel.HIGH,
                scanner="prompt_flow",
                explanation=(
                    f"Credentials or secrets were found at: {', '.join(secret_locations)}. "
                    "Secrets in the prompt flow are logged, appear in LLM context windows, "
                    "and can be exfiltrated via prompt injection."
                ),
                impact="Credential leakage via LLM context, logs, or injection attacks.",
                remediation="Remove credentials from all prompt flow stages. Use runtime secret injection "
                             "(environment variables, secret managers) rather than passing secrets through "
                             "prompts or tool responses.",
                evidence=[Evidence("prompt_flow", "secret_locations", secret_locations,
                                   "Secret patterns found at these flow stages")],
                mitre_atlas=["AML.T0051"],
            ))

        policy_bypass = bool(injection_reach and tool_calls)
        rag_override = "memory_rag" in injection_reach

        if rag_override:
            findings.append(Finding(
                id="PF-RAG-OVERRIDE",
                title="RAG/memory context can override system instructions",
                severity=Severity.HIGH, confidence=ConfidenceLevel.HIGH,
                scanner="prompt_flow",
                explanation="Injection patterns were found in retrieved context (memory/RAG). "
                            "If the retrieved documents contain adversarial instructions, they can "
                            "override the system prompt and redirect the agent.",
                impact="Indirect prompt injection via poisoned knowledge base or vector store.",
                remediation="Sanitise documents before indexing. Use structured retrieval formats "
                             "rather than free-text. Apply relevance + safety filters on retrieved chunks.",
                evidence=[Evidence("prompt_flow", "memory_rag", mem_data[:200],
                                   "Injection pattern in retrieved context")],
                mitre_atlas=["AML.T0051", "AML.T0054"],
            ))

        summary_parts = [f"Flow stages: {len(nodes)}"]
        if injection_reach: summary_parts.append(f"Injection-reachable: {len(injection_reach)}")
        if secret_locations: summary_parts.append(f"Secret exposure: {len(secret_locations)} stage(s)")
        if policy_bypass: summary_parts.append("Policy bypass risk: YES")

        return PromptFlowReport(
            nodes=nodes, edges=edges, findings=findings,
            injection_reach=injection_reach,
            secret_exposure=secret_locations,
            policy_bypass_risk=policy_bypass,
            rag_override_risk=rag_override,
            summary=" | ".join(summary_parts),
        )

    def analyse_static(self, system_prompt: str = "", tools: list[str] = None,
                       has_rag: bool = False, has_memory: bool = False) -> PromptFlowReport:
        """Static analysis without a runtime session."""
        nodes, edges, findings = [], [], []
        injection_reach, secret_locations = [], []

        # System prompt analysis
        sp_risk, sp_findings = "safe", []
        if system_prompt:
            _, sp_findings = self._check_injection(system_prompt, "system prompt")
            if self._check_secrets(system_prompt):
                sp_risk = "critical"
                secret_locations.append("system_prompt")
                findings.append(Finding(
                    id="SPF-SECRET-IN-SYSPROMPT",
                    title="Credentials in system prompt",
                    severity=Severity.CRITICAL, confidence=ConfidenceLevel.HIGH,
                    scanner="prompt_flow_static",
                    explanation="The system prompt contains what appears to be credentials or secrets. "
                                "These will be included in every LLM context window.",
                    impact="Secrets exposed in every request — visible in logs and injectable via prompt attacks.",
                    remediation="Remove all credentials from system prompts. Inject via runtime environment.",
                    evidence=[Evidence("system_prompt", "content", system_prompt[:200],
                                       "Secret pattern matched in system prompt")],
                    mitre_atlas=["AML.T0051"],
                ))

        nodes.append(FlowNode("user_input", "User Input", "input", "(user-supplied)", "high",
                               ["Attacker-controlled input"]))
        nodes.append(FlowNode("system_prompt", "System Prompt", "context",
                               system_prompt[:100], sp_risk, sp_findings))

        if has_rag:
            nodes.append(FlowNode("rag", "RAG / Retrieved Docs", "context",
                                   "(external content)", "medium",
                                   ["External content — injection risk if not sanitised"]))
            injection_reach.append("rag_context")

        if has_memory:
            nodes.append(FlowNode("memory", "Agent Memory", "context",
                                   "(persisted state)", "medium", []))

        nodes.append(FlowNode("llm", "LLM", "processing",
                               "(processes all context)", "high" if injection_reach else "medium", []))

        if tools:
            for t in tools:
                nodes.append(FlowNode(f"tool_{t}", f"Tool: {t}", "processing",
                                       "(tool invocation)", "medium", []))
                injection_reach.append(f"tool_{t}_args")

        nodes.append(FlowNode("response", "LLM Response", "output", "(generated output)", "low", []))

        return PromptFlowReport(
            nodes=nodes, edges=[], findings=findings,
            injection_reach=injection_reach,
            secret_exposure=secret_locations,
            policy_bypass_risk=bool(tools and has_rag),
            rag_override_risk=has_rag,
            summary=f"Static flow analysis | {len(nodes)} stages | "
                    f"injection reach: {len(injection_reach)} | secrets: {len(secret_locations)}",
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _check_injection(self, text: str, source: str) -> tuple[str, list[str]]:
        if not text: return "safe", []
        issues = []
        for pattern, label, _ in INJECTION_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                issues.append(f"Injection: {label}")
        risk = "critical" if issues else "safe"
        return risk, issues

    def _check_secrets(self, text: str) -> bool:
        if not text: return False
        for pattern, _ in SECRET_PATTERNS:
            if re.search(pattern, text):
                return True
        return False
