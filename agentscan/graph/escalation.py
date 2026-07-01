# -*- coding: utf-8 -*-
"""
Capability Escalation Analysis
================================
Measures how individually-harmless capabilities combine into dangerous
exploit chains -- the AI-agent equivalent of privilege escalation analysis
in cloud IAM security (e.g. how Wiz/Orca find IAM privilege escalation paths).

Core idea: a single capability (e.g. "read files") is low risk.
But CHAINS of capabilities create escalation:

  read_files (low) -> can read SSH keys
    -> ssh_exec (medium) -> can connect to other hosts
      -> cloud_api (high) -> can assume IAM roles
        -> admin access (critical)

This produces an "escalation score" per capability -- not just its
standalone risk, but how much risk it ADDS when combined with what's
already present in the agent's capability set.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from itertools import combinations

from agentscan.models import Finding, Evidence, Severity, ConfidenceLevel


# Escalation rules: (capability_set_required) -> (resulting_escalated_capability, explanation)
# Modelled after cloud IAM privilege escalation patterns (iam:PassRole, lambda:UpdateFunctionCode, etc.)
ESCALATION_RULES: list[dict] = [
    {
        "id": "ESC-FILE-TO-CRED",
        "requires": {"file_read"},
        "escalates_to": "secret_access",
        "title": "File read escalates to credential access",
        "explanation": (
            "Filesystem read access alone seems low-risk, but it commonly grants access to "
            "credential files (~/.aws/credentials, .env, ssh keys, service account JSON). "
            "This is functionally equivalent to secret_access even though it wasn't declared as such."
        ),
        "severity": Severity.HIGH,
        "mitre": ["AML.T0051"],
    },
    {
        "id": "ESC-SECRET-TO-CLOUD",
        "requires": {"secret_access", "network_egress"},
        "escalates_to": "cloud_api",
        "title": "Secret access + network escalates to cloud control plane access",
        "explanation": (
            "An agent with secret access and network egress can retrieve cloud credentials "
            "and then use them directly via the cloud provider's HTTP API -- achieving full "
            "cloud_api capability without ever being granted a 'cloud_api' tool."
        ),
        "severity": Severity.CRITICAL,
        "mitre": ["AML.T0048", "AML.T0051"],
    },
    {
        "id": "ESC-SHELL-TO-ALL",
        "requires": {"shell_exec"},
        "escalates_to": "*",  # shell access escalates to everything
        "title": "Shell execution escalates to unrestricted system access",
        "explanation": (
            "Shell execution is a universal escalation primitive -- from a shell, an agent can "
            "read any file, access any credential, make any network call, and install persistence. "
            "Any other declared capability becomes redundant once shell_exec is present; "
            "shell_exec should be treated as equivalent to root access."
        ),
        "severity": Severity.CRITICAL,
        "mitre": ["AML.T0017", "AML.T0048"],
    },
    {
        "id": "ESC-CODE-TO-SHELL",
        "requires": {"code_execution"},
        "escalates_to": "shell_exec",
        "title": "Code execution escalates to shell execution",
        "explanation": (
            "Code interpreters (Python REPL, Jupyter, eval) can call os.system(), subprocess, "
            "or equivalent -- meaning code_execution capability is functionally equivalent to "
            "shell_exec even if the tool was scoped as 'just run Python'."
        ),
        "severity": Severity.CRITICAL,
        "mitre": ["AML.T0017"],
    },
    {
        "id": "ESC-DB-TO-FILE",
        "requires": {"database"},
        "escalates_to": "file_write",
        "title": "Database access escalates to filesystem write (via SQL features)",
        "explanation": (
            "Many databases support file-writing SQL functions (MySQL INTO OUTFILE, "
            "PostgreSQL COPY TO, SQL Server xp_cmdshell). An agent with raw SQL access "
            "can often write arbitrary files to the host filesystem."
        ),
        "severity": Severity.HIGH,
        "mitre": ["AML.T0048"],
    },
    {
        "id": "ESC-EMAIL-TO-EXFIL",
        "requires": {"email_send"},
        "escalates_to": "network_egress",
        "title": "Email send escalates to data exfiltration channel",
        "explanation": (
            "Email sending is a complete exfiltration channel even without explicit "
            "network_egress capability -- any data the agent can read can be emailed out."
        ),
        "severity": Severity.MEDIUM,
        "mitre": ["AML.T0040"],
    },
    {
        "id": "ESC-MEMORY-TO-PERSIST",
        "requires": {"memory_write", "code_execution"},
        "escalates_to": "persistence",
        "title": "Memory write + code execution escalates to persistent backdoor",
        "explanation": (
            "An agent that can write to its own persistent memory AND execute code can "
            "implant instructions that survive across sessions -- a persistence mechanism "
            "equivalent to a backdoor, triggered automatically on every future invocation."
        ),
        "severity": Severity.CRITICAL,
        "mitre": ["AML.T0018", "AML.T0048"],
    },
    {
        "id": "ESC-VECTORDB-TO-INJECT",
        "requires": {"vector_db", "memory_write"},
        "escalates_to": "persistent_injection",
        "title": "Vector DB write escalates to persistent prompt injection",
        "explanation": (
            "An agent that can write to the vector store used for RAG can poison future "
            "retrievals for itself or OTHER agents sharing the same vector store -- "
            "a multi-agent, multi-session injection vector."
        ),
        "severity": Severity.CRITICAL,
        "mitre": ["AML.T0020", "AML.T0051"],
    },
]

# Base risk weight per capability (for computing escalation delta)
BASE_RISK = {
    "shell_exec": 40, "code_execution": 40, "secret_access": 35,
    "cloud_api": 30, "database": 25, "file_write": 20, "network_egress": 15,
    "file_read": 10, "email_send": 10, "memory_write": 8, "memory_read": 3,
    "vector_db": 3, "persistence": 45, "persistent_injection": 45,
}


@dataclass
class EscalationPath:
    """A capability combination that escalates beyond its declared scope."""
    rule_id: str
    title: str
    required_caps: set[str]
    escalates_to: str
    explanation: str
    severity: Severity
    base_risk: int           # sum of declared capability risk
    escalated_risk: int      # risk after escalation
    risk_delta: int          # how much MORE dangerous than it looks
    mitre_atlas: list[str]


@dataclass
class EscalationReport:
    """Complete capability escalation analysis."""
    declared_capabilities: set[str]
    declared_risk: int               # risk score from declared capabilities alone
    effective_capabilities: set[str] # capabilities INCLUDING escalations
    effective_risk: int              # true risk including escalation
    escalation_paths: list[EscalationPath]
    findings: list[Finding]
    escalation_factor: float         # effective_risk / declared_risk


def analyse_capability_escalation(capabilities: list[str]) -> EscalationReport:
    """
    Given a set of declared capabilities, find all escalation paths
    and compute the TRUE effective risk vs the DECLARED risk.
    """
    declared = set(capabilities)
    declared_risk = min(sum(BASE_RISK.get(c, 5) for c in declared), 100)

    escalation_paths: list[EscalationPath] = []
    effective = set(declared)

    # Iteratively apply escalation rules until no new capabilities are added
    changed = True
    iterations = 0
    while changed and iterations < 10:
        changed = False
        iterations += 1
        for rule in ESCALATION_RULES:
            if rule["requires"].issubset(effective):
                target = rule["escalates_to"]
                if target == "*":
                    # Shell escalates to everything -- special case
                    new_caps = set(BASE_RISK.keys()) - effective
                    if new_caps:
                        effective |= new_caps
                        changed = True
                elif target not in effective:
                    effective.add(target)
                    changed = True

                # Record the escalation path (once per rule)
                if not any(p.rule_id == rule["id"] for p in escalation_paths):
                    base = min(sum(BASE_RISK.get(c, 5) for c in rule["requires"]), 100)
                    esc_risk = base + BASE_RISK.get(target, 20) if target != "*" else 100
                    escalation_paths.append(EscalationPath(
                        rule_id=rule["id"],
                        title=rule["title"],
                        required_caps=rule["requires"],
                        escalates_to=target,
                        explanation=rule["explanation"],
                        severity=rule["severity"],
                        base_risk=base,
                        escalated_risk=min(esc_risk, 100),
                        risk_delta=min(esc_risk, 100) - base,
                        mitre_atlas=rule["mitre"],
                    ))

    effective_risk = min(sum(BASE_RISK.get(c, 5) for c in effective), 100)
    escalation_factor = round(effective_risk / max(declared_risk, 1), 2)

    # Build findings
    findings: list[Finding] = []
    for path in sorted(escalation_paths, key=lambda p: -p.risk_delta):
        findings.append(Finding(
            id=f"ESCALATION-{path.rule_id}",
            title=path.title,
            severity=path.severity,
            confidence=ConfidenceLevel.MEDIUM,  # escalation is inferred, not directly observed
            scanner="capability_escalation",
            explanation=path.explanation,
            impact=(
                f"Declared capabilities {sorted(path.required_caps)} effectively grant "
                f"'{path.escalates_to}' capability -- a risk increase of {path.risk_delta} points "
                f"that is NOT reflected in the agent's declared permission set."
            ),
            remediation=(
                f"Either explicitly acknowledge that {sorted(path.required_caps)} grants "
                f"'{path.escalates_to}'-equivalent access in your risk assessment, or implement "
                "compensating controls (sandboxing, allowlisting, read-only mounts) that prevent "
                "the escalation path from being exploitable."
            ),
            evidence=[Evidence(
                source="capability_escalation_rules",
                field="required_capabilities",
                observed_value=sorted(path.required_caps),
                explanation=f"Rule {path.rule_id}: {sorted(path.required_caps)} -> {path.escalates_to}",
            )],
            mitre_atlas=path.mitre_atlas,
            tags=["capability-escalation", path.rule_id.lower()],
        ))

    # Summary finding if escalation factor is high
    if escalation_factor >= 1.5:
        findings.insert(0, Finding(
            id="ESCALATION-SUMMARY",
            title=f"True risk is {escalation_factor}x higher than declared capabilities suggest",
            severity=Severity.CRITICAL if escalation_factor >= 2 else Severity.HIGH,
            confidence=ConfidenceLevel.MEDIUM,
            scanner="capability_escalation",
            explanation=(
                f"Based on declared capabilities alone, this agent scores {declared_risk}/100 risk. "
                f"But {len(escalation_paths)} escalation path(s) mean the EFFECTIVE risk is "
                f"{effective_risk}/100 -- a {escalation_factor}x increase. This gap is exactly "
                "where security reviews based on declared permissions alone go wrong."
            ),
            impact="Security review based on declared capabilities significantly underestimates true risk.",
            remediation=(
                "Use effective risk (not declared risk) for security sign-off decisions. "
                "Review each escalation path and implement compensating controls."
            ),
            evidence=[Evidence(
                source="escalation_analysis",
                field="declared_vs_effective",
                observed_value={"declared": declared_risk, "effective": effective_risk},
                explanation=f"{len(escalation_paths)} escalation paths found",
            )],
            mitre_atlas=["AML.T0048"],
            tags=["capability-escalation", "summary"],
        ))

    return EscalationReport(
        declared_capabilities=declared,
        declared_risk=declared_risk,
        effective_capabilities=effective,
        effective_risk=effective_risk,
        escalation_paths=escalation_paths,
        findings=findings,
        escalation_factor=escalation_factor,
    )
