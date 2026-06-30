"""JSON and SARIF output renderers for CI/CD integration."""

from __future__ import annotations
import json
from agentscan.models import Finding, ScanResult


def to_dict(result: ScanResult) -> dict:
    """Serialise a ScanResult to a plain dict (JSON-serialisable)."""
    return {
        "agentscan_version": "0.1.0",
        "target": result.target,
        "scanner_type": result.scanner_type,
        "risk_score": result.risk_score(),
        "scan_duration_ms": result.scan_duration_ms,
        "error": result.error,
        "summary": {
            "critical": result.critical_count,
            "high": result.high_count,
            "total_findings": len(result.reportable_findings),
            "attack_paths": len(result.attack_paths),
        },
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "scanner": f.scanner,
                "explanation": f.explanation,
                "impact": f.impact,
                "remediation": f.remediation,
                "mitre_atlas": f.mitre_atlas,
                "cwe": f.cwe,
                "evidence": [
                    {
                        "source": e.source,
                        "field": e.field,
                        "observed_value": str(e.observed_value),
                        "explanation": e.explanation,
                    }
                    for e in f.evidence
                ],
                "tags": f.tags,
            }
            for f in result.reportable_findings
        ],
        "attack_paths": [
            {
                "id": p.id,
                "title": p.title,
                "severity": p.severity.value,
                "entry_point": p.entry_point,
                "impact": p.impact,
                "description": p.description,
                "mitre_atlas": p.mitre_atlas,
                "step_ids": [s.id for s in p.steps],
            }
            for p in result.attack_paths
        ],
        "metadata": result.metadata,
    }


def to_json(result: ScanResult, indent: int = 2) -> str:
    return json.dumps(to_dict(result), indent=indent)


def to_sarif(result: ScanResult) -> str:
    """
    SARIF 2.1.0 output — integrates with GitHub Advanced Security,
    VS Code, and any SARIF-compatible tool.
    """
    rules = []
    results = []
    seen_rule_ids: set[str] = set()

    for finding in result.reportable_findings:
        if finding.id not in seen_rule_ids:
            seen_rule_ids.add(finding.id)
            rules.append({
                "id": finding.id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.explanation},
                "help": {"text": finding.remediation, "markdown": f"**Fix:** {finding.remediation}"},
                "properties": {
                    "tags": finding.tags + finding.mitre_atlas,
                    "security-severity": {
                        "CRITICAL": "9.0", "HIGH": "7.0", "MEDIUM": "5.0", "LOW": "3.0", "INFO": "1.0"
                    }.get(finding.severity.value, "1.0"),
                },
            })

        results.append({
            "ruleId": finding.id,
            "level": {
                "CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "none"
            }.get(finding.severity.value, "note"),
            "message": {"text": f"{finding.explanation}\n\nImpact: {finding.impact}\n\nFix: {finding.remediation}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": result.target}}}],
            "properties": {"confidence": finding.confidence.value},
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "AgentScan",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/agentscan/agentscan",
                    "rules": rules,
                }
            },
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)
