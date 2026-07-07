# -*- coding: utf-8 -*-
"""
Compliance Framework Mapper
============================
Maps AgentScan findings to specific controls across:
  - RBI AI-ACT&RS + MRM 2026 (India)
  - DPDP Act 2023 + Rules 2025 (India)
  - SEBI CSCRF (India)
  - ISO/IEC 42001:2023 (International)
  - EU AI Act 2024/1689 (EU)
  - NIST AI RMF 1.0 (US)
  - SOC 2 TSP 100 (International)

Every finding tag or capability maps to a set of control references.
The mapper produces a compliance gap report showing which controls
are implicated by the findings in a scan result.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from agentscan.models import ScanResult, Severity


@dataclass
class ControlReference:
    framework: str
    control_id: str
    control_name: str
    obligation: str       # what the control requires
    how_finding_maps: str # plain English: why this finding triggers this control
    severity: str         # "mandatory" | "recommended"
    requirement_level: str = "mandatory"
    owner: str = "Engineering / Security"
    deadline: str = "TBD"
    evidence_status: str = "not-assessed"


@dataclass
class ComplianceMapping:
    finding_id: str
    finding_title: str
    finding_severity: str
    controls: list[ControlReference] = field(default_factory=list)


@dataclass
class ComplianceReport:
    target: str
    frameworks_covered: list[str]
    mappings: list[ComplianceMapping]
    control_summary: dict[str, int]   # framework -> number of controls implicated
    overall_posture: str              # "compliant" | "partial" | "non-compliant"
    priority_gaps: list[str]          # top 3 things to fix for compliance
    resolved_mappings: list[ComplianceMapping] = None  # dispositioned findings, kept visible, not counted


# -- Control library ---------------------------------------------------------
# Keyed by finding tag or capability name.
# Each entry is a list of control references across frameworks.

CONTROL_LIBRARY: dict[str, list[dict]] = {

    "shell_exec": [
        {"framework": "RBI MRM 2026", "control_id": "MRM-4.3",
         "control_name": "Autonomous action boundaries",
         "obligation": "High-autonomy AI systems must have defined boundaries preventing execution of OS-level commands without human approval.",
         "severity": "mandatory"},
        {"framework": "RBI AI-ACT&RS", "control_id": "AIACTS-2.1",
         "control_name": "AI system privilege minimisation",
         "obligation": "Regulated entities must ensure AI systems operate with minimum required privileges.",
         "severity": "mandatory"},
        {"framework": "ISO 42001", "control_id": "ISO42001-8.4",
         "control_name": "AI system operational controls",
         "obligation": "Organizations shall implement controls to limit AI system actions to defined operational boundaries.",
         "severity": "mandatory"},
        {"framework": "EU AI Act", "control_id": "AIA-Art9",
         "control_name": "Risk management system",
         "obligation": "High-risk AI systems require a risk management system identifying risks from unintended actions.",
         "severity": "mandatory"},
        {"framework": "NIST AI RMF", "control_id": "MANAGE-2.4",
         "control_name": "Risk treatment for AI actions",
         "obligation": "Residual risks from AI autonomous actions shall be treated via controls or acceptance.",
         "severity": "recommended"},
        {"framework": "SOC 2", "control_id": "CC6.1",
         "control_name": "Logical access controls",
         "obligation": "The entity implements logical access security measures to protect against threats from outside the system.",
         "severity": "mandatory"},
    ],

    "secret_access": [
        {"framework": "RBI AI-ACT&RS", "control_id": "AIACTS-3.2",
         "control_name": "Credential protection for AI systems",
         "obligation": "AI systems must not have direct access to production credentials. Secret retrieval must be audited and logged.",
         "severity": "mandatory"},
        {"framework": "DPDP Rules 2025", "control_id": "DPDP-R8",
         "control_name": "Reasonable security safeguards",
         "obligation": "Data fiduciaries must implement reasonable security safeguards including access controls for systems processing personal data.",
         "severity": "mandatory"},
        {"framework": "ISO 42001", "control_id": "ISO42001-8.5",
         "control_name": "AI data and resource access controls",
         "obligation": "Access to sensitive resources by AI systems shall be controlled and logged.",
         "severity": "mandatory"},
        {"framework": "SOC 2", "control_id": "CC6.3",
         "control_name": "Authorised access to credentials",
         "obligation": "The entity authorizes, modifies, or removes access to data, software, functions, and other protected resources.",
         "severity": "mandatory"},
        {"framework": "EU AI Act", "control_id": "AIA-Art10",
         "control_name": "Data governance",
         "obligation": "Training, validation, and testing data as well as model access must be governed with appropriate access controls.",
         "severity": "mandatory"},
    ],

    "network_egress": [
        {"framework": "RBI Cybersecurity Framework", "control_id": "RBI-CSF-5.3",
         "control_name": "Network egress controls",
         "obligation": "Outbound network connections from AI systems must be restricted to approved destinations and logged.",
         "severity": "mandatory"},
        {"framework": "DPDP Rules 2025", "control_id": "DPDP-R8",
         "control_name": "Data transfer safeguards",
         "obligation": "Personal data must not be transferred outside India to restricted countries. Outbound AI network calls must be audited.",
         "severity": "mandatory"},
        {"framework": "SEBI CSCRF", "control_id": "SEBI-CSCRF-4.2",
         "control_name": "Data loss prevention",
         "obligation": "Market intermediaries must implement DLP controls including monitoring of outbound data from AI systems.",
         "severity": "mandatory"},
        {"framework": "ISO 42001", "control_id": "ISO42001-8.4",
         "control_name": "AI output controls",
         "obligation": "Outputs from AI systems, including network-based outputs, must be controlled and monitored.",
         "severity": "mandatory"},
        {"framework": "SOC 2", "control_id": "CC6.6",
         "control_name": "Network boundary protection",
         "obligation": "The entity implements controls to prevent unauthorized outbound data transmission.",
         "severity": "mandatory"},
    ],

    "database": [
        {"framework": "DPDP Rules 2025", "control_id": "DPDP-R8",
         "control_name": "Database access controls for AI",
         "obligation": "AI systems with database access must operate on least-privilege principles; access must be logged and auditable.",
         "severity": "mandatory"},
        {"framework": "RBI AI-ACT&RS", "control_id": "AIACTS-3.1",
         "control_name": "Sensitive data access by AI",
         "obligation": "AI systems accessing customer or financial data must be logged, scoped, and subject to periodic review.",
         "severity": "mandatory"},
        {"framework": "ISO 42001", "control_id": "ISO42001-8.3",
         "control_name": "AI input data controls",
         "obligation": "Data used by AI systems, including database queries, must be governed with appropriate controls.",
         "severity": "mandatory"},
        {"framework": "SOC 2", "control_id": "CC7.2",
         "control_name": "Anomalous data access monitoring",
         "obligation": "The entity monitors for unusual database access patterns including AI-initiated queries.",
         "severity": "mandatory"},
    ],

    "file_write": [
        {"framework": "RBI Cybersecurity Framework", "control_id": "RBI-CSF-3.4",
         "control_name": "Integrity controls",
         "obligation": "AI systems must not modify configuration or system files without explicit authorisation and audit trail.",
         "severity": "mandatory"},
        {"framework": "ISO 42001", "control_id": "ISO42001-8.4",
         "control_name": "AI system output integrity",
         "obligation": "AI-generated outputs that modify persistent data must be controlled and reversible.",
         "severity": "mandatory"},
        {"framework": "SOC 2", "control_id": "CC6.8",
         "control_name": "Unauthorised software controls",
         "obligation": "The entity implements controls to prevent unauthorised software from being installed or run.",
         "severity": "mandatory"},
    ],

    "code_execution": [
        {"framework": "RBI MRM 2026", "control_id": "MRM-4.3",
         "control_name": "Code execution boundaries",
         "obligation": "AI systems capable of executing code must be sandboxed and subject to kill-switch controls.",
         "severity": "mandatory"},
        {"framework": "EU AI Act", "control_id": "AIA-Art14",
         "control_name": "Human oversight of autonomous code execution",
         "obligation": "High-risk AI systems with code execution capability require human oversight mechanisms and override capability.",
         "severity": "mandatory"},
        {"framework": "ISO 42001", "control_id": "ISO42001-8.4",
         "control_name": "AI operational boundaries",
         "obligation": "AI systems shall operate within defined operational boundaries; code execution requires explicit boundary definition.",
         "severity": "mandatory"},
    ],

    "mcp-auth": [
        {"framework": "RBI AI-ACT&RS", "control_id": "AIACTS-2.3",
         "control_name": "Third-party AI tool authentication",
         "obligation": "All third-party AI tools and servers must require authentication before accepting requests.",
         "severity": "mandatory"},
        {"framework": "ISO 42001", "control_id": "ISO42001-8.6",
         "control_name": "Third-party AI system controls",
         "obligation": "Third-party AI systems must be assessed and controlled; authentication is a baseline requirement.",
         "severity": "mandatory"},
        {"framework": "SEBI CSCRF", "control_id": "SEBI-CSCRF-3.1",
         "control_name": "Vendor access controls",
         "obligation": "Market intermediaries must ensure third-party AI vendors implement access controls.",
         "severity": "mandatory"},
        {"framework": "SOC 2", "control_id": "CC9.2",
         "control_name": "Vendor risk management",
         "obligation": "The entity assesses and monitors vendors whose products or services could affect security.",
         "severity": "mandatory"},
    ],

    "supply-chain": [
        {"framework": "RBI AI-ACT&RS", "control_id": "AIACTS-4.1",
         "control_name": "AI supply chain risk",
         "obligation": "Regulated entities must assess the security posture of AI models, libraries, and tools before deployment.",
         "severity": "mandatory"},
        {"framework": "ISO 42001", "control_id": "ISO42001-8.6",
         "control_name": "AI supply chain controls",
         "obligation": "Organizations shall establish controls for AI supply chain risks including model provenance and dataset integrity.",
         "severity": "mandatory"},
        {"framework": "EU AI Act", "control_id": "AIA-Art25",
         "control_name": "Obligations of deployers",
         "obligation": "Deployers of AI systems must verify provenance and compliance of AI systems they deploy.",
         "severity": "mandatory"},
        {"framework": "NIST AI RMF", "control_id": "MAP-5.1",
         "control_name": "AI supply chain transparency",
         "obligation": "Practices and results related to AI risks associated with the supply chain shall be disclosed.",
         "severity": "recommended"},
        {"framework": "SEBI CSCRF", "control_id": "SEBI-CSCRF-5.1",
         "control_name": "Third-party software risk",
         "obligation": "Market intermediaries must assess third-party AI software including models and packages for supply chain risk.",
         "severity": "mandatory"},
    ],

    "missing-control": [
        {"framework": "RBI MRM 2026", "control_id": "MRM-3.2",
         "control_name": "AI guardrails requirement",
         "obligation": "High-risk AI models must have output safety controls and guardrails as a precondition for deployment.",
         "severity": "mandatory"},
        {"framework": "EU AI Act", "control_id": "AIA-Art16",
         "control_name": "Technical documentation -- safety measures",
         "obligation": "High-risk AI systems must document safety measures and controls implemented.",
         "severity": "mandatory"},
        {"framework": "ISO 42001", "control_id": "ISO42001-8.4",
         "control_name": "AI output safety controls",
         "obligation": "Organizations shall implement controls to ensure AI outputs are safe and aligned with intended purpose.",
         "severity": "mandatory"},
    ],
}

# DPDP-specific gap: things AgentScan cannot assess but must flag
DPDP_STATIC_GAPS = [
    {
        "gap": "Consent mechanism not assessed",
        "control": "DPDP-R3",
        "detail": "DPDP Rules 2025 Rule 3 requires a standalone consent notice before any personal data collection. AgentScan cannot assess whether your agent's consent flow is compliant -- this requires a manual privacy review.",
        "deadline": "May 13, 2027",
    },
    {
        "gap": "Data retention policy not assessed",
        "control": "DPDP-R9",
        "detail": "DPDP requires personal data to be deleted once the purpose is fulfilled. Agent memory and conversation logs must be covered by a defined retention and deletion policy.",
        "deadline": "May 13, 2027",
    },
    {
        "gap": "Breach notification procedure not assessed",
        "control": "DPDP-R6",
        "detail": "DPDP requires notification to the Data Protection Board and affected individuals within 72 hours of a personal data breach. Your agent deployment must have a breach detection and notification procedure.",
        "deadline": "November 2026 (phase 2)",
    },
    {
        "gap": "DPIA not conducted",
        "control": "DPDP-SDF-2",
        "detail": "Significant Data Fiduciaries must conduct a Data Protection Impact Assessment annually. Use the AgentScan DPIA module to generate a DPIA based on this scan's findings.",
        "deadline": "May 13, 2027",
    },
]


def detect_audit_evidence(target_path: str) -> str:
    """Check whether the scanned codebase contains common audit/logging evidence."""
    path = Path(target_path)
    if not path.exists():
        return "not-found"

    evidence_markers = [
        "logging", "audit", "audit_log", "audit_logs", "logger", "structured_log",
        "cloudtrail", "opentelemetry", "sentry", "prometheus", "monitoring",
    ]

    for candidate in path.rglob("*"):
        if not candidate.is_file():
            continue
        try:
            text = candidate.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        lowered = text.lower()
        if any(marker in lowered for marker in evidence_markers):
            return "present"
    return "not-found"


def calculate_compliance_score(report: ComplianceReport) -> int:
    """
    Return a 0-100 posture score based on OPEN findings (report.mappings is
    pre-filtered to open findings only by map_findings_to_controls -- a
    dispositioned finding does not appear here at all).

    Weighted per FINDING, not per control. The previous formula gave every
    implicated control a flat 25-point penalty with no per-finding cap --
    since a single finding routinely maps to 4+ mandatory controls
    simultaneously (RBI + DPDP + ISO 42001 + SOC 2 all regulate the same
    underlying capability), one heavily-regulated finding could already
    saturate weighted_failures past 100 regardless of how many total
    findings existed. That made the score a de facto binary 0-or-100 gate
    that never moved even after resolving most of a scan's findings --
    exactly the reported symptom ("5 of 7 findings dispositioned... still
    0/100"). Capping the penalty per finding (based on the finding's own
    severity, not how many frameworks happen to regulate it) makes the
    score actually graduated and responsive to real triage progress.
    """
    if not report.mappings:
        return 100

    SEVERITY_PENALTY = {"CRITICAL": 22, "HIGH": 14, "MEDIUM": 6, "LOW": 2, "INFO": 0}

    weighted_failures = 0.0
    for mapping in report.mappings:
        weighted_failures += SEVERITY_PENALTY.get(mapping.finding_severity, 10)

    return max(0, min(100, int(100 - min(weighted_failures, 100))))


def map_findings_to_controls(result: ScanResult) -> ComplianceReport:
    """
    Takes a ScanResult and returns a ComplianceReport mapping
    each finding to the compliance controls it implicates.

    Only OPEN findings (see risk_register.filter_by_disposition) count
    toward the active control mappings, posture, and score -- a finding
    marked accepted_risk / false_positive / remediated has been reviewed
    and should move the compliance posture, not sit there looking identical
    to an unreviewed CRITICAL finding. Resolved findings are NOT dropped
    from the report entirely -- they're mapped separately into
    resolved_mappings so the full audit trail (what was found, what was
    decided, why) stays visible, just no longer counted against the score.
    """
    from agentscan.risk_register import filter_by_disposition
    disposition = filter_by_disposition(result)

    mappings: list[ComplianceMapping] = []
    resolved_mappings: list[ComplianceMapping] = []
    framework_control_counts: dict[str, set] = {}

    evidence_status = detect_audit_evidence(result.target)

    def _build_mappings_for(findings_list, target_list, count_toward_frameworks):
        for finding in findings_list:
            if finding not in result.reportable_findings:
                continue
            controls: list[ControlReference] = []
            for tag in finding.tags:
                if tag in CONTROL_LIBRARY:
                    for c in CONTROL_LIBRARY[tag]:
                        fw = c["framework"]
                        cid = c["control_id"]
                        if count_toward_frameworks:
                            framework_control_counts.setdefault(fw, set()).add(cid)
                        requirement_level = "mandatory" if c["severity"] == "mandatory" else "recommended"
                        owner = "Engineering / Security"
                        deadline = "30 days" if requirement_level == "mandatory" else "90 days"
                        if fw in {"SOC 2", "NIST AI RMF"}:
                            owner = "Security / Compliance"
                            deadline = "90 days"
                        elif fw in {"RBI AI-ACT&RS", "RBI MRM 2026", "DPDP Rules 2025", "SEBI CSCRF"}:
                            owner = "Security / Compliance / Legal"
                            deadline = "14 days"

                        finding_status = getattr(finding, "status", "open")
                        this_evidence_status = evidence_status
                        how_maps = f"Finding '{finding.title}' triggers this control because the agent capability '{tag}' is directly regulated."
                        if finding_status != "open":
                            # Evidence status must reflect the disposition, not
                            # silently keep showing "not found" for a finding
                            # that's been confirmed wrong or already fixed --
                            # that was the exact bug reported.
                            this_evidence_status = {
                                "accepted_risk": "accepted",
                                "false_positive": "not-applicable",
                                "remediated": "remediated",
                            }.get(finding_status, evidence_status)
                            status_record = getattr(finding, "status_record", None) or {}
                            how_maps += (
                                f" Status: {finding_status.replace('_', ' ').title()}"
                                f" (reviewed by {status_record.get('reviewer', 'Unknown')}"
                                f" on {status_record.get('set_at', '')}"
                                f" -- {status_record.get('reason', '')})."
                            )

                        controls.append(ControlReference(
                            framework=fw, control_id=cid, control_name=c["control_name"],
                            obligation=c["obligation"], how_finding_maps=how_maps,
                            severity=c["severity"], requirement_level=requirement_level,
                            owner=owner, deadline=deadline, evidence_status=this_evidence_status,
                        ))
            if controls:
                target_list.append(ComplianceMapping(
                    finding_id=finding.id, finding_title=finding.title,
                    finding_severity=finding.severity.value, controls=controls,
                ))

    _build_mappings_for(disposition["open_findings"], mappings, count_toward_frameworks=True)
    _build_mappings_for(disposition["resolved_findings"], resolved_mappings, count_toward_frameworks=False)

    # Determine overall posture -- based on OPEN findings/paths only. A
    # finding or attack path that's been reviewed and dispositioned
    # (accepted with compensating controls, proven false, or already fixed)
    # is a fundamentally different governance state than an unreviewed one,
    # and must be able to move the posture from NON-COMPLIANT toward
    # COMPLIANT -- otherwise a full triage pass changes nothing the reader
    # sees first, which is the exact confusion reported.
    open_findings = disposition["open_findings"]
    open_paths = disposition["open_paths"]
    open_critical_count = sum(1 for f in open_findings if f.severity.value == "CRITICAL")
    open_high_count = sum(1 for f in open_findings if f.severity.value == "HIGH")
    has_open_attack_paths = bool(open_paths)

    if open_critical_count >= 2 or has_open_attack_paths:
        posture = "non-compliant"
    elif open_critical_count == 1 or open_high_count >= 3:
        posture = "partial"
    else:
        posture = "compliant"

    # Priority gaps -- also computed from open findings/paths only
    priority_gaps = []
    if open_paths:
        priority_gaps.append(f"Resolve {len(open_paths)} critical attack path(s) before any compliance claim is valid")
    if any("secret_access" in f.tags for f in open_findings):
        priority_gaps.append("Restrict agent access to secrets -- this is a mandatory RBI and DPDP control")
    if any("mcp-auth" in f.tags for f in open_findings):
        priority_gaps.append("Add authentication to all MCP servers -- required under RBI AI-ACT&RS and ISO 42001")
    if not priority_gaps:
        priority_gaps.append("Run the DPIA module to generate the required Data Protection Impact Assessment")
        priority_gaps.append("Generate audit report for board sign-off (RBI MRM 2026 requirement)")

    # Derive the covered-frameworks list from the framework names that
    # actually appear in CONTROL_LIBRARY. Round 3 QA: the header
    # previously hardcoded a list ("DPDP Act 2023", "RBI AI-ACT&RS") that
    # diverged from the names cited in the per-finding control table
    # ("DPDP Rules 2025", "RBI Cybersecurity Framework"). Deriving both
    # from the same source keeps a compliance artifact internally
    # consistent -- exactly the property an audit reviewer checks.
    covered: set[str] = set()
    for entries in CONTROL_LIBRARY.values():
        for entry in entries:
            covered.add(entry["framework"])

    return ComplianceReport(
        target=result.target,
        frameworks_covered=sorted(covered),
        mappings=mappings,
        control_summary={fw: len(ids) for fw, ids in framework_control_counts.items()},
        overall_posture=posture,
        priority_gaps=priority_gaps[:3],
        resolved_mappings=resolved_mappings,
    )
