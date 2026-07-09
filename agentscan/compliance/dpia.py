# -*- coding: utf-8 -*-
"""
DPIA Module -- Data Protection Impact Assessment Generator
==========================================================
Generates a structured DPIA document based on AgentScan findings.

Required by:
  - DPDP Act 2023 / Rules 2025 (Significant Data Fiduciaries)
  - EU AI Act Article 9 (high-risk AI systems)
  - ISO 42001 Clause 8.7 (AI impact assessment)
  - RBI MRM 2026 (pre-deployment risk assessment for high-tier models)

The DPIA ingests scan findings and produces a structured document
that can be submitted to auditors or the Data Protection Board.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import date
from agentscan.models import ScanResult, Severity


@dataclass
class DPIASection:
    title: str
    content: str
    status: str      # "adequate" | "gap" | "not-assessed"
    controls: list[str] = field(default_factory=list)


@dataclass
class DPIADocument:
    agent_name: str
    assessment_date: str
    assessor: str
    scan_target: str
    sections: list[DPIASection]
    overall_risk_level: str    # "low" | "medium" | "high" | "critical"
    recommended_action: str    # "deploy" | "deploy-with-controls" | "do-not-deploy"
    compliance_frameworks: list[str]
    open_gaps: list[str]


def generate_dpia(result: ScanResult, agent_name: str = "AI Agent", assessor: str = "AgentScan") -> DPIADocument:
    """
    Generate a DPIA document from scan results.
    Sections follow the structure expected by DPDP auditors and ISO 42001 Clause 8.7.
    """
    from agentscan.risk_register import filter_by_disposition, annotate_findings, compute_governed_score
    disposition = filter_by_disposition(result)
    open_findings_objs = disposition["open_findings"]
    open_paths = disposition["open_paths"]

    findings = result.reportable_findings
    caps = result.metadata.get("capabilities_detected", []) or []
    tool_count = result.metadata.get("tools_found", result.metadata.get("tool_count", 0))
    if not caps:
        caps = sorted({tag for f in findings for tag in getattr(f, "tags", []) if tag not in {"tool-permissions", "source-extracted", "behavioral-detection", "name-description-mismatch"}})
    if not tool_count:
        tool_count = max(1, len(findings))

    sections: list[DPIASection] = []

    # -- Section 1: System Description ---------------------------------------
    cap_desc = ", ".join(caps) if caps else "No capabilities detected"
    sections.append(DPIASection(
        title="1. AI System Description",
        content=(
            f"Agent name: {agent_name}\n"
            f"Scan target: {result.target}\n"
            f"Scanner type: {result.scanner_type}\n"
            f"Tool count: {tool_count}\n"
            f"Capability count: {len(caps)}\n"
            f"Detected capabilities: {cap_desc}\n\n"
            "This assessment covers the security and data protection posture of the above AI agent "
            "configuration as scanned by AgentScan. The assessment evaluates tool permissions, "
            "data access patterns, and attack surface in accordance with DPDP Act 2023, "
            "RBI MRM 2026, and ISO 42001 requirements."
        ),
        status="adequate",
        controls=["DPDP-R3", "ISO42001-8.7", "AIA-Art11"],
    ))

    # -- Section 2: Necessity and Proportionality -----------------------------
    high_risk_caps = [c for c in caps if c in ("shell_exec", "secret_access", "code_execution", "database")]
    if high_risk_caps:
        necessity_status = "gap"
        necessity_content = (
            f"The agent has {len(high_risk_caps)} high-risk capability class(es): {', '.join(high_risk_caps)}.\n\n"
            "DPDP and ISO 42001 require that data processing be necessary and proportionate to the stated purpose. "
            f"The following capabilities require documented justification:\n\n"
        )
        for cap in high_risk_caps:
            necessity_content += f"  * {cap}: Justify why this capability is necessary for the agent's stated purpose.\n"
        necessity_content += (
            "\nAction required: For each high-risk capability, document the business necessity, "
            "the data minimisation measures applied, and why less intrusive alternatives were rejected."
        )
    else:
        necessity_status = "adequate"
        necessity_content = (
            "No high-risk capabilities (shell execution, secret access, code execution, database) "
            "were detected. The agent's tool set appears proportionate to typical AI assistant tasks. "
            "Document the agent's stated purpose and confirm tool selection aligns with that purpose."
        )

    sections.append(DPIASection(
        title="2. Necessity and Proportionality Assessment",
        content=necessity_content,
        status=necessity_status,
        controls=["DPDP-R3", "ISO42001-8.3", "AIA-Art9"],
    ))

    # -- Section 3: Risk Identification --------------------------------------
    # Uses only OPEN findings/paths (see risk_register.filter_by_disposition)
    # for the headline risk list -- a finding proven false or already fixed
    # must not keep appearing here identically to an unreviewed CRITICAL.
    # Dispositioned findings are still shown, in a separate "Reviewed" block,
    # so the DPIA remains a complete audit trail rather than silently
    # dropping anything.
    risk_items = []
    for f in open_findings_objs:
        if f.severity in (Severity.CRITICAL, Severity.HIGH):
            risk_items.append(f"  [{f.severity.value}] {f.title}\n    Impact: {f.impact}\n    MITRE: {', '.join(f.mitre_atlas)}")

    attack_path_items = []
    for p in open_paths:
        attack_path_items.append(f"  [CRITICAL PATH] {p.title}\n    Entry: {p.entry_point}\n    Impact: {p.impact}")

    resolved_items = []
    for f in disposition["resolved_findings"]:
        if f.severity in (Severity.CRITICAL, Severity.HIGH):
            status = getattr(f, "status", "open").replace("_", " ").title()
            record = getattr(f, "status_record", None) or {}
            resolved_items.append(
                f"  [{status}] {f.title}\n"
                f"    Reviewed by {record.get('reviewer', 'Unknown')} on {record.get('set_at', '')}: {record.get('reason', '')}"
            )

    risk_content = "Identified risks from AgentScan analysis:\n\n"
    if attack_path_items:
        risk_content += "Attack paths (complete exploit chains):\n" + "\n".join(attack_path_items) + "\n\n"
    if risk_items:
        risk_content += "Individual findings:\n" + "\n".join(risk_items) + "\n\n"
    if not risk_items and not attack_path_items:
        risk_content += "No open critical or high-severity risks identified in static analysis.\n\n"
    if resolved_items:
        risk_content += (
            "Reviewed and dispositioned (excluded from the risk count above, but retained "
            "here for audit trail completeness):\n" + "\n".join(resolved_items) + "\n\n"
        )

    risk_content += (
        "Note: This assessment covers static configuration analysis. "
        "Runtime risks (prompt injection in production, data leakage via actual user interactions) "
        "require runtime monitoring which is not covered by this static scan."
    )

    sections.append(DPIASection(
        title="3. Risk Identification",
        content=risk_content,
        status="gap" if risk_items or attack_path_items else "adequate",
        controls=["DPDP-R8", "RBI-AIACTS-2.1", "ISO42001-8.4", "AIA-Art9"],
    ))

    # -- Section 4: Data Flows and Personal Data Processing ------------------
    data_flow_gaps = []
    if "database" in caps:
        data_flow_gaps.append("Agent has database access -- map which tables contain personal data and document access scope")
    if "file_read" in caps or "file_write" in caps:
        data_flow_gaps.append("Agent has filesystem access -- identify which files may contain personal data")
    if "network_egress" in caps:
        data_flow_gaps.append("Agent can make outbound requests -- audit whether personal data leaves the system boundary")
    if "email_send" in caps:
        data_flow_gaps.append("Agent can send emails -- ensure personal data in emails is minimised and consented")

    df_content = (
        "Personal data flows must be documented for DPDP compliance. "
        "AgentScan identified the following data flow risks:\n\n"
    )
    if data_flow_gaps:
        for gap in data_flow_gaps:
            df_content += f"  [!] {gap}\n"
        df_status = "gap"
    else:
        df_content += "  No high-risk data flow capabilities detected in agent configuration.\n"
        df_status = "adequate"

    df_content += (
        "\nAction required: Complete a data flow mapping exercise documenting:\n"
        "  1. What personal data the agent processes\n"
        "  2. Where it is stored (agent memory, databases, logs)\n"
        "  3. Whether it crosses borders (DPDP data localisation)\n"
        "  4. Retention period and deletion mechanism"
    )

    sections.append(DPIASection(
        title="4. Data Flows and Personal Data Processing",
        content=df_content,
        status=df_status,
        controls=["DPDP-R3", "DPDP-R9", "DPDP-R8"],
    ))

    # -- Section 5: Controls and Mitigations ---------------------------------
    has_guardrails = not any("missing-control" in f.tags for f in findings)
    controls_content = "Controls identified and gaps:\n\n"

    controls_implemented = []
    controls_missing = []

    if has_guardrails:
        controls_implemented.append("Output guardrails / content filter configured")
    else:
        controls_missing.append("Output guardrails -- required under RBI MRM 2026 Tier-3 and ISO 42001 Clause 8.4")

    if "shell_exec" not in caps and "code_execution" not in caps:
        controls_implemented.append("No code/shell execution capability (reduces blast radius)")
    else:
        controls_missing.append("Sandbox for code/shell execution -- required before production deployment")

    if "secret_access" not in caps:
        controls_implemented.append("No direct secret access (secrets should be injected at runtime)")
    else:
        controls_missing.append("Secret access audit logging -- every credential retrieval must be logged and alertable")

    for c in controls_implemented:
        controls_content += f"  [OK] {c}\n"
    for c in controls_missing:
        controls_content += f"  [X] {c}\n"

    sections.append(DPIASection(
        title="5. Controls and Mitigations",
        content=controls_content,
        status="gap" if controls_missing else "adequate",
        controls=["RBI-MRM-3.2", "ISO42001-8.4", "AIA-Art16", "SOC2-CC6.1"],
    ))

    # -- Section 6: Residual Risk and Recommendation -------------------------
    # Uses the GOVERNED score and OPEN attack paths -- a "DO NOT DEPLOY"
    # verdict must reflect actual triage. If 2 of 3 attack-path-driving
    # findings have been confirmed false or already fixed, the deploy
    # recommendation must change accordingly, not keep citing the original
    # pre-review numbers as if no review had happened.
    _finding_dicts = [{"id": f.id, "severity": f.severity.value} for f in (result.findings or [])]
    annotate_findings(_finding_dicts, result.target)
    _scores = compute_governed_score(_finding_dicts)
    risk_score = _scores["governed_score"]
    open_path_count = len(open_paths)

    if risk_score >= 70 or open_paths:
        overall_risk = "critical"
        recommendation = "do-not-deploy"
        rec_text = (
            f"Governed risk score: {risk_score}/100. {open_path_count} open attack path(s) remain.\n\n"
            "RECOMMENDATION: DO NOT DEPLOY without remediation.\n"
            "The agent configuration presents critical security risks that would result in non-compliance "
            "with RBI AI-ACT&RS, DPDP Act reasonable security safeguard requirements, and ISO 42001 "
            "operational controls. Address all open CRITICAL and HIGH findings before deployment."
        )
    elif risk_score >= 40:
        overall_risk = "high"
        recommendation = "deploy-with-controls"
        rec_text = (
            f"Governed risk score: {risk_score}/100.\n\n"
            "RECOMMENDATION: DEPLOY WITH CONTROLS.\n"
            "The configuration has significant risks that must be mitigated. "
            "Implement compensating controls (network allowlisting, audit logging, runtime monitoring) "
            "and re-scan before production deployment."
        )
    elif risk_score >= 15:
        overall_risk = "medium"
        recommendation = "deploy-with-controls"
        rec_text = (
            f"Governed risk score: {risk_score}/100.\n\n"
            "RECOMMENDATION: DEPLOY WITH MONITORING.\n"
            "The configuration presents moderate risks. Deploy with runtime monitoring enabled "
            "and schedule a re-assessment within 90 days."
        )
    else:
        overall_risk = "low"
        recommendation = "deploy"
        rec_text = (
            f"Governed risk score: {risk_score}/100.\n\n"
            "RECOMMENDATION: DEPLOY.\n"
            "The configuration presents low risk. Maintain regular re-assessment schedule "
            "(quarterly recommended by ISO 42001 and RBI MRM 2026)."
        )

    sections.append(DPIASection(
        title="6. Residual Risk and Deployment Recommendation",
        content=rec_text,
        status="gap" if recommendation == "do-not-deploy" else "adequate",
        controls=["ISO42001-8.7", "AIA-Art9", "RBI-MRM-4.1"],
    ))

    # Open gaps (things AgentScan can't assess)
    open_gaps = [
        "Consent mechanism compliance (requires manual privacy review of user-facing flows)",
        "Data retention and deletion policy (requires documentation review)",
        "72-hour breach notification procedure (requires process review)",
        "Runtime behaviour monitoring (requires deployment of runtime agent instrumentation)",
        "Human override / kill-switch documentation (requires governance review)",
    ]

    return DPIADocument(
        agent_name=agent_name,
        assessment_date=date.today().isoformat(),
        assessor=assessor,
        scan_target=result.target,
        sections=sections,
        overall_risk_level=overall_risk,
        recommended_action=recommendation,
        compliance_frameworks=["DPDP Act 2023", "RBI MRM 2026", "ISO 42001", "EU AI Act", "SOC 2"],
        open_gaps=open_gaps,
    )
