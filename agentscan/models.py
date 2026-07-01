# -*- coding: utf-8 -*-
"""
Core data models used across all scanners.
All findings carry confidence scores and evidence chains to minimise false positives.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ConfidenceLevel(str, Enum):
    """
    AgentScan only reports findings above MEDIUM confidence.
    HIGH = multiple independent signals confirm the risk.
    MEDIUM = one strong signal with structural evidence.
    LOW = heuristic only -- suppressed by default to reduce noise.
    """
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Evidence:
    """A concrete piece of evidence supporting a finding."""
    source: str           # e.g. "tool_definition", "metadata", "network_call"
    field: str            # e.g. "tools[2].permissions", "publisher.created_at"
    observed_value: Any   # what was actually found
    explanation: str      # plain-English explanation of why this matters


@dataclass
class Finding:
    """
    A security finding from any scanner.
    Findings include:
      - severity + confidence so consumers can filter appropriately
      - evidence chain so users understand *why* the finding exists
      - remediation so users know exactly what to do
      - mitre_atlas mapping for enterprise alignment
    """
    id: str
    title: str
    severity: Severity
    confidence: ConfidenceLevel
    scanner: str                        # which scanner produced this
    explanation: str                    # what is happening, in plain English
    impact: str                         # what an attacker could do if exploited
    remediation: str                    # concrete step to fix it
    evidence: list[Evidence] = field(default_factory=list)
    mitre_atlas: list[str] = field(default_factory=list)  # e.g. ["AML.T0051"]
    cwe: list[str] = field(default_factory=list)          # e.g. ["CWE-272"]
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    def is_reportable(self) -> bool:
        """Suppress LOW confidence findings unless explicitly requested."""
        return self.confidence != ConfidenceLevel.LOW


@dataclass
class AttackPath:
    """
    A chained sequence of findings that together represent an exploitable path
    from an attacker-controlled entry point to a high-value impact.
    """
    id: str
    title: str
    severity: Severity
    steps: list[Finding]
    entry_point: str    # e.g. "prompt injection via user input"
    impact: str         # e.g. "AWS credential exfiltration"
    description: str    # narrative explanation of the full path
    mitre_atlas: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    """Top-level result object returned by any scan command."""
    target: str
    scanner_type: str
    findings: list[Finding] = field(default_factory=list)
    attack_paths: list[AttackPath] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    scan_duration_ms: int = 0
    error: str | None = None

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL and f.is_reportable())

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH and f.is_reportable())

    @property
    def reportable_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.is_reportable()]

    def risk_score(self) -> int:
        """0-100 composite risk score weighted by severity."""
        weights = {Severity.CRITICAL: 40, Severity.HIGH: 20, Severity.MEDIUM: 8, Severity.LOW: 2}
        score = sum(weights.get(f.severity, 0) for f in self.reportable_findings)
        return min(score, 100)
