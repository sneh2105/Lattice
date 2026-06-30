"""
Terminal output renderer — produces beautiful, informative CLI output.
Designed to be screenshot-worthy and shareable.
"""

from __future__ import annotations
import sys
from agentscan.models import AttackPath, Finding, ScanResult, Severity, ConfidenceLevel

# ANSI colours
RED = "\033[91m"
ORANGE = "\033[33m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
GREEN = "\033[92m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"
WHITE = "\033[97m"

SEVERITY_COLOUR = {
    Severity.CRITICAL: RED,
    Severity.HIGH: ORANGE,
    Severity.MEDIUM: YELLOW,
    Severity.LOW: BLUE,
    Severity.INFO: DIM,
}

SEVERITY_ICON = {
    Severity.CRITICAL: "✗",
    Severity.HIGH: "!",
    Severity.MEDIUM: "▲",
    Severity.LOW: "·",
    Severity.INFO: "ℹ",
}


def _supports_colour() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _col(colour: str, text: str) -> str:
    if not _supports_colour():
        return text
    return f"{colour}{text}{RESET}"


def _severity_badge(sev: Severity) -> str:
    colour = SEVERITY_COLOUR.get(sev, "")
    icon = SEVERITY_ICON.get(sev, "?")
    label = sev.value
    return _col(colour, f"[{icon} {label}]")


def _hr(width: int = 70, char: str = "─") -> str:
    return _col(DIM, char * width)


def render_result(result: ScanResult, verbose: bool = False) -> str:
    lines: list[str] = []
    w = 70

    # ── Header ──────────────────────────────────────────────────────────
    lines.append("")
    lines.append(_col(BOLD + CYAN, "  AgentScan " + "─" * 50))
    lines.append(_col(DIM, f"  target  : {result.target}"))
    lines.append(_col(DIM, f"  scanner : {result.scanner_type}"))
    lines.append(_col(DIM, f"  duration: {result.scan_duration_ms}ms"))
    lines.append("")

    # ── Error ────────────────────────────────────────────────────────────
    if result.error:
        lines.append(_col(RED, f"  ✗ Error: {result.error}"))
        lines.append("")
        return "\n".join(lines)

    # ── Risk Score ───────────────────────────────────────────────────────
    score = result.risk_score()
    if score >= 80:
        score_col = RED
    elif score >= 50:
        score_col = ORANGE
    elif score >= 20:
        score_col = YELLOW
    else:
        score_col = GREEN

    bar_filled = int(score / 5)
    bar = "█" * bar_filled + "░" * (20 - bar_filled)
    lines.append(_col(BOLD, f"  Risk score  ") + _col(score_col, f"{score:3d}/100  ") + _col(score_col, bar))
    lines.append("")

    # ── Finding counts ───────────────────────────────────────────────────
    reportable = result.reportable_findings
    counts = {sev: 0 for sev in Severity}
    for f in reportable:
        counts[f.severity] += 1

    parts = []
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        if counts[sev]:
            parts.append(_col(SEVERITY_COLOUR[sev], f"{counts[sev]} {sev.value}"))
    lines.append("  Findings: " + "  ".join(parts) if parts else "  " + _col(GREEN, "✓ No reportable findings"))

    if result.attack_paths:
        lines.append(_col(RED + BOLD, f"  Attack paths: {len(result.attack_paths)} critical chain(s) found"))
    lines.append("")

    # ── Attack paths (most important, shown first) ───────────────────────
    if result.attack_paths:
        lines.append(_col(BOLD + RED, "  ╔══ ATTACK PATHS ══════════════════════════════════════════╗"))
        for i, path in enumerate(result.attack_paths, 1):
            lines.append(_col(RED, f"  ║  {i}. {path.title}"))
            lines.append(_col(DIM, f"  ║     Entry : {path.entry_point}"))
            lines.append(_col(DIM, f"  ║     Impact: {path.impact}"))
            # Show chain
            step_names = [s.title.split("'")[1] if "'" in s.title else s.title[:40] for s in path.steps[:4]]
            if step_names:
                chain = " → ".join(step_names)
                lines.append(_col(ORANGE, f"  ║     Chain : {chain}"))
            if path.mitre_atlas:
                lines.append(_col(DIM, f"  ║     ATLAS : {', '.join(path.mitre_atlas)}"))
            lines.append(_col(DIM, "  ║"))
        lines.append(_col(BOLD + RED, "  ╚═══════════════════════════════════════════════════════════╝"))
        lines.append("")

    # ── Individual findings ──────────────────────────────────────────────
    if reportable:
        lines.append(_col(BOLD, "  ── Findings " + "─" * 55))
        lines.append("")

        # Sort: critical first
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        sorted_findings = sorted(reportable, key=lambda f: severity_order.index(f.severity))

        for finding in sorted_findings:
            badge = _severity_badge(finding.severity)
            conf_str = _col(DIM, f"[confidence: {finding.confidence.value}]")
            lines.append(f"  {badge} {_col(BOLD, finding.title)} {conf_str}")
            lines.append("")

            # What is happening
            lines.append(_col(CYAN, "  What's happening:"))
            for chunk in _wrap(finding.explanation, 64):
                lines.append(f"    {chunk}")
            lines.append("")

            # Impact
            lines.append(_col(ORANGE, "  Impact:"))
            lines.append(f"    {finding.impact}")
            lines.append("")

            # Evidence
            if finding.evidence:
                lines.append(_col(BLUE, "  Evidence:"))
                for ev in finding.evidence:
                    lines.append(_col(DIM, f"    source : {ev.source}"))
                    lines.append(_col(DIM, f"    field  : {ev.field}"))
                    val_str = str(ev.observed_value)
                    if len(val_str) > 80:
                        val_str = val_str[:77] + "..."
                    lines.append(_col(DIM, f"    value  : {val_str}"))
                    lines.append(_col(DIM, f"    reason : {ev.explanation}"))
                lines.append("")

            # Remediation
            lines.append(_col(GREEN, "  Fix:"))
            for chunk in _wrap(finding.remediation, 64):
                lines.append(f"    {chunk}")

            # MITRE / CWE
            if finding.mitre_atlas:
                lines.append(_col(DIM, f"  MITRE ATLAS: {', '.join(finding.mitre_atlas)}"))
            if finding.cwe:
                lines.append(_col(DIM, f"  CWE: {', '.join(finding.cwe)}"))

            lines.append("")
            lines.append(_col(DIM, "  " + "·" * 66))
            lines.append("")

    # ── Metadata ────────────────────────────────────────────────────────
    if verbose and result.metadata:
        lines.append(_col(DIM, "  ── Metadata " + "─" * 55))
        for k, v in result.metadata.items():
            lines.append(_col(DIM, f"  {k}: {v}"))
        lines.append("")

    # ── Footer ───────────────────────────────────────────────────────────
    lines.append(_col(DIM, "  AgentScan v0.1.0 · github.com/sneh2105/agentscan"))
    lines.append("")
    return "\n".join(lines)


def _wrap(text: str, width: int) -> list[str]:
    """Simple word-wrap."""
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        if len(current) + len(word) + 1 > width:
            if current:
                lines.append(current)
            current = word
        else:
            current = (current + " " + word).strip()
    if current:
        lines.append(current)
    return lines or [""]
