# -*- coding: utf-8 -*-
"""
Audit Report Generator
=======================
Generates a board-level PDF compliance evidence document.

This is the artifact you hand to:
  - RBI inspector (board sign-off requirement, MRM 2026)
  - ISO 42001 auditor (Clause 9.1 performance evaluation)
  - CERT-In empanelled auditor (VAPT evidence)
  - DPDP Data Protection Board (breach investigation, SDF audit)
  - SOC 2 auditor (CC evidence package)

Format: structured PDF with executive summary, findings table,
compliance control mapping, DPIA summary, and sign-off section.
"""

from __future__ import annotations
from datetime import date
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

from agentscan.models import ScanResult, Severity
from agentscan.compliance.framework_mapper import map_findings_to_controls, DPDP_STATIC_GAPS
from agentscan.compliance.dpia import generate_dpia


# -- Colour palette -----------------------------------------------------------
DARK = colors.HexColor("#1a1a2e")
ACCENT = colors.HexColor("#16213e")
BLUE = colors.HexColor("#0f3460")
TEAL = colors.HexColor("#1d7a8c")
RED_DARK = colors.HexColor("#a32d2d")
ORANGE = colors.HexColor("#c47a1e")
GREEN_DARK = colors.HexColor("#2d6a2d")
LIGHT_BG = colors.HexColor("#f8f9fa")
MID_GREY = colors.HexColor("#6c757d")
BORDER = colors.HexColor("#dee2e6")

SEV_COLOURS = {
    "CRITICAL": RED_DARK,
    "HIGH": ORANGE,
    "MEDIUM": colors.HexColor("#856404"),
    "LOW": BLUE,
    "INFO": MID_GREY,
}


def _styles():
    base = getSampleStyleSheet()
    return {
        "cover_title": ParagraphStyle("cover_title", fontSize=26, textColor=colors.white,
                                       spaceAfter=6, leading=32, fontName="Helvetica-Bold"),
        "cover_sub": ParagraphStyle("cover_sub", fontSize=13, textColor=colors.HexColor("#adb5bd"),
                                     spaceAfter=4, leading=18, fontName="Helvetica"),
        "section_head": ParagraphStyle("section_head", fontSize=13, textColor=BLUE,
                                        spaceBefore=14, spaceAfter=6, fontName="Helvetica-Bold",
                                        borderPad=4),
        "body": ParagraphStyle("body", fontSize=9, textColor=DARK, spaceAfter=4,
                                leading=14, fontName="Helvetica"),
        "small": ParagraphStyle("small", fontSize=8, textColor=MID_GREY, spaceAfter=2,
                                 leading=12, fontName="Helvetica"),
        "bold": ParagraphStyle("bold", fontSize=9, textColor=DARK, fontName="Helvetica-Bold",
                               spaceAfter=4, leading=14),
        "label": ParagraphStyle("label", fontSize=8, textColor=MID_GREY, fontName="Helvetica",
                                leading=12),
        "risk_critical": ParagraphStyle("risk_critical", fontSize=18, textColor=RED_DARK,
                                         fontName="Helvetica-Bold", leading=22),
        "risk_ok": ParagraphStyle("risk_ok", fontSize=18, textColor=GREEN_DARK,
                                   fontName="Helvetica-Bold", leading=22),
    }


def _severity_cell(sev: str) -> Paragraph:
    col = SEV_COLOURS.get(sev, MID_GREY)
    return Paragraph(
        f'<font color="white"><b> {sev} </b></font>',
        ParagraphStyle("sev", fontSize=7, backColor=col, textColor=colors.white,
                       fontName="Helvetica-Bold", borderPad=2, leading=11)
    )


def generate_audit_report(
    result: ScanResult,
    output_path: str,
    agent_name: str = "AI Agent",
    organisation: str = "Organisation",
    assessor: str = "AgentScan",
    include_dpia: bool = True,
) -> str:
    """Generate a PDF audit report. Returns the output path."""
    output_path = str(Path(output_path).with_suffix(".pdf"))
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=20*mm, bottomMargin=20*mm,
        title=f"AgentScan Compliance Audit Report -- {agent_name}",
        author="AgentScan",
    )

    S = _styles()
    story = []
    W = 170*mm  # usable width

    compliance_report = map_findings_to_controls(result)
    dpia = generate_dpia(result, agent_name=agent_name, assessor=assessor) if include_dpia else None

    # -- COVER PAGE -----------------------------------------------------------
    cover_table = Table([[
        Table([
            [Paragraph("AgentScan", S["cover_title"])],
            [Paragraph("AI Agent Security &amp; Compliance Audit Report", S["cover_sub"])],
            [Spacer(1, 8*mm)],
            [Paragraph(f"<b>Agent:</b> {agent_name}", S["cover_sub"])],
            [Paragraph(f"<b>Organisation:</b> {organisation}", S["cover_sub"])],
            [Paragraph(f"<b>Assessment date:</b> {date.today().strftime('%B %d, %Y')}", S["cover_sub"])],
            [Paragraph(f"<b>Assessor:</b> {assessor}", S["cover_sub"])],
            [Spacer(1, 8*mm)],
            [Paragraph("Frameworks covered", S["cover_sub"])],
            [Paragraph("RBI AI-ACT&RS  -  RBI MRM 2026  -  DPDP Act 2023  -  SEBI CSCRF  -  ISO 42001  -  EU AI Act  -  NIST AI RMF  -  SOC 2",
                       ParagraphStyle("fw", fontSize=9, textColor=colors.HexColor("#74b9ff"), leading=14))],
        ], colWidths=[W])
    ]], colWidths=[W])
    cover_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), DARK),
        ("PADDING", (0, 0), (-1, -1), 16),
        ("ROWHEIGHT", (0, 0), (-1, -1), 180*mm),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(cover_table)
    story.append(PageBreak())

    # -- EXECUTIVE SUMMARY ----------------------------------------------------
    story.append(Paragraph("Executive Summary", S["section_head"]))
    story.append(HRFlowable(width=W, thickness=1, color=BLUE, spaceAfter=6))

    risk_score = result.risk_score()
    posture_colour = RED_DARK if compliance_report.overall_posture == "non-compliant" else \
                     ORANGE if compliance_report.overall_posture == "partial" else GREEN_DARK
    posture_label = compliance_report.overall_posture.upper().replace("-", " ")

    exec_data = [
        ["Risk Score", "Compliance Posture", "Critical Findings", "Attack Paths", "Frameworks Assessed"],
        [
            Paragraph(f"<b>{risk_score}/100</b>", ParagraphStyle("rs", fontSize=16,
                      textColor=posture_colour, fontName="Helvetica-Bold", leading=20)),
            Paragraph(f"<b>{posture_label}</b>", ParagraphStyle("cp", fontSize=11,
                      textColor=posture_colour, fontName="Helvetica-Bold", leading=14)),
            Paragraph(f"<b>{result.critical_count}</b>",
                      ParagraphStyle("cf", fontSize=16, textColor=RED_DARK,
                                     fontName="Helvetica-Bold", leading=20)),
            Paragraph(f"<b>{len(result.attack_paths)}</b>",
                      ParagraphStyle("ap", fontSize=16, textColor=RED_DARK if result.attack_paths else GREEN_DARK,
                                     fontName="Helvetica-Bold", leading=20)),
            Paragraph(f"<b>{len(compliance_report.frameworks_covered)}</b>",
                      ParagraphStyle("fa", fontSize=16, textColor=BLUE,
                                     fontName="Helvetica-Bold", leading=20)),
        ]
    ]
    exec_table = Table(exec_data, colWidths=[W/5]*5)
    exec_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), BLUE),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("BACKGROUND", (0, 1), (-1, 1), LIGHT_BG),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ROWHEIGHT", (0, 1), (-1, 1), 40),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
        ("PADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(exec_table)
    story.append(Spacer(1, 6*mm))

    # Priority gaps
    if compliance_report.priority_gaps:
        story.append(Paragraph("Priority actions required:", S["bold"]))
        for i, gap in enumerate(compliance_report.priority_gaps, 1):
            story.append(Paragraph(f"{i}. {gap}", S["body"]))
    story.append(Spacer(1, 4*mm))

    # -- ATTACK PATHS --------------------------------------------------------
    if result.attack_paths:
        story.append(Paragraph("Critical Attack Paths", S["section_head"]))
        story.append(HRFlowable(width=W, thickness=1, color=RED_DARK, spaceAfter=6))
        story.append(Paragraph(
            "The following attack paths represent complete exploit chains -- sequences of capabilities "
            "that together allow an attacker to cause significant harm. These must be resolved before "
            "any compliance claim is valid.",
            S["body"]
        ))
        story.append(Spacer(1, 3*mm))

        for path in result.attack_paths:
            path_data = [
                [Paragraph(f"<b>{path.title}</b>",
                            ParagraphStyle("pt", fontSize=9, textColor=RED_DARK,
                                           fontName="Helvetica-Bold", leading=13)), ""],
                [Paragraph("Entry point", S["label"]), Paragraph(path.entry_point, S["body"])],
                [Paragraph("Impact", S["label"]), Paragraph(path.impact, S["body"])],
                [Paragraph("MITRE ATLAS", S["label"]),
                 Paragraph(", ".join(path.mitre_atlas), S["body"])],
                [Paragraph("Chain", S["label"]),
                 Paragraph(" -> ".join([s.title[:50] for s in path.steps[:4]]), S["small"])],
            ]
            path_table = Table(path_data, colWidths=[30*mm, W - 30*mm])
            path_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#fdf0f0")),
                ("SPAN", (0, 0), (-1, 0)),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#f5c6c6")),
                ("PADDING", (0, 0), (-1, -1), 6),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (0, -1), 8),
            ]))
            story.append(path_table)
            story.append(Spacer(1, 3*mm))

    # -- FINDINGS TABLE -------------------------------------------------------
    story.append(PageBreak())
    story.append(Paragraph("Security Findings", S["section_head"]))
    story.append(HRFlowable(width=W, thickness=1, color=BLUE, spaceAfter=6))

    findings_header = [
        Paragraph("Severity", ParagraphStyle("fh", fontSize=8, textColor=colors.white,
                                             fontName="Helvetica-Bold")),
        Paragraph("Finding", ParagraphStyle("fh", fontSize=8, textColor=colors.white,
                                            fontName="Helvetica-Bold")),
        Paragraph("Impact", ParagraphStyle("fh", fontSize=8, textColor=colors.white,
                                           fontName="Helvetica-Bold")),
        Paragraph("Remediation", ParagraphStyle("fh", fontSize=8, textColor=colors.white,
                                                fontName="Helvetica-Bold")),
    ]
    findings_rows = [findings_header]

    sev_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
    sorted_findings = sorted(result.reportable_findings,
                             key=lambda f: sev_order.index(f.severity) if f.severity in sev_order else 99)

    for f in sorted_findings:
        findings_rows.append([
            _severity_cell(f.severity.value),
            Paragraph(f.title, S["small"]),
            Paragraph(f.impact[:120], S["small"]),
            Paragraph(f.remediation[:150], S["small"]),
        ])

    if not sorted_findings:
        findings_rows.append([
            Paragraph("--", S["small"]),
            Paragraph("No reportable findings", S["body"]),
            Paragraph("--", S["small"]),
            Paragraph("--", S["small"]),
        ])

    findings_table = Table(findings_rows, colWidths=[22*mm, 48*mm, 50*mm, 50*mm])
    findings_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), BLUE),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
        ("PADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_BG]),
    ]))
    story.append(findings_table)

    # -- COMPLIANCE CONTROL MAPPING -------------------------------------------
    story.append(PageBreak())
    story.append(Paragraph("Compliance Control Mapping", S["section_head"]))
    story.append(HRFlowable(width=W, thickness=1, color=BLUE, spaceAfter=6))
    story.append(Paragraph(
        "The following table maps each finding to the specific regulatory controls it implicates. "
        "This mapping serves as evidence for auditors across all covered frameworks.",
        S["body"]
    ))
    story.append(Spacer(1, 3*mm))

    ctrl_header = [
        Paragraph(h, ParagraphStyle("ch", fontSize=8, textColor=colors.white, fontName="Helvetica-Bold"))
        for h in ["Framework", "Control ID", "Control", "Finding", "Obligation"]
    ]
    ctrl_rows = [ctrl_header]

    for mapping in compliance_report.mappings:
        for ctrl in mapping.controls:
            ctrl_rows.append([
                Paragraph(ctrl.framework, S["small"]),
                Paragraph(ctrl.control_id, ParagraphStyle("cid", fontSize=7, textColor=BLUE,
                                                           fontName="Helvetica-Bold", leading=10)),
                Paragraph(ctrl.control_name, S["small"]),
                Paragraph(mapping.finding_title[:60], S["small"]),
                Paragraph(ctrl.obligation[:100], S["small"]),
            ])

    if len(ctrl_rows) == 1:
        ctrl_rows.append([Paragraph("--", S["small"])] * 5)

    ctrl_table = Table(ctrl_rows, colWidths=[30*mm, 22*mm, 35*mm, 40*mm, 43*mm])
    ctrl_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), TEAL),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
        ("PADDING", (0, 0), (-1, -1), 4),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_BG]),
        ("FONTSIZE", (0, 1), (-1, -1), 7),
    ]))
    story.append(ctrl_table)

    # -- DPDP GAPS ------------------------------------------------------------
    story.append(Spacer(1, 6*mm))
    story.append(Paragraph("DPDP Act -- Items Requiring Manual Review", S["section_head"]))
    story.append(HRFlowable(width=W, thickness=1, color=TEAL, spaceAfter=6))
    story.append(Paragraph(
        "AgentScan covers security safeguards. The following DPDP obligations require "
        "manual review by your privacy/legal team and cannot be assessed by static scanning.",
        S["body"]
    ))
    story.append(Spacer(1, 3*mm))

    for gap in DPDP_STATIC_GAPS:
        gap_data = [
            [Paragraph(f"[!] {gap['gap']}", ParagraphStyle("gg", fontSize=9, textColor=ORANGE,
                                                           fontName="Helvetica-Bold", leading=13)),
             Paragraph(f"Control: {gap['control']}  |  Deadline: {gap['deadline']}",
                       S["small"])],
            [Paragraph(gap["detail"], S["small"]), ""],
        ]
        gap_table = Table(gap_data, colWidths=[W*0.6, W*0.4])
        gap_table.setStyle(TableStyle([
            ("SPAN", (0, 1), (-1, 1)),
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fff9f0")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#ffe4b3")),
            ("PADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(gap_table)
        story.append(Spacer(1, 2*mm))

    # -- DPIA SUMMARY ---------------------------------------------------------
    if dpia:
        story.append(PageBreak())
        story.append(Paragraph("Data Protection Impact Assessment (DPIA)", S["section_head"]))
        story.append(HRFlowable(width=W, thickness=1, color=TEAL, spaceAfter=6))
        story.append(Paragraph(
            f"Required by: DPDP Act 2023 (Significant Data Fiduciaries)  -  ISO 42001 Clause 8.7  -  EU AI Act Article 9",
            S["small"]
        ))
        story.append(Spacer(1, 3*mm))

        risk_col = RED_DARK if dpia.overall_risk_level in ("critical", "high") else \
                   ORANGE if dpia.overall_risk_level == "medium" else GREEN_DARK
        rec_col = RED_DARK if dpia.recommended_action == "do-not-deploy" else \
                  ORANGE if dpia.recommended_action == "deploy-with-controls" else GREEN_DARK

        dpia_summary = Table([
            [Paragraph("Overall Risk Level", S["label"]),
             Paragraph(dpia.overall_risk_level.upper(),
                       ParagraphStyle("drl", fontSize=11, textColor=risk_col,
                                      fontName="Helvetica-Bold", leading=14)),
             Paragraph("Recommendation", S["label"]),
             Paragraph(dpia.recommended_action.upper().replace("-", " "),
                       ParagraphStyle("rec", fontSize=9, textColor=rec_col,
                                      fontName="Helvetica-Bold", leading=12))],
        ], colWidths=[30*mm, 50*mm, 30*mm, 60*mm])
        dpia_summary.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), LIGHT_BG),
            ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
            ("PADDING", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(dpia_summary)
        story.append(Spacer(1, 4*mm))

        for section in dpia.sections:
            status_col = GREEN_DARK if section.status == "adequate" else \
                         ORANGE if section.status == "gap" else MID_GREY
            status_label = {"adequate": "ADEQUATE", "gap": "GAP IDENTIFIED",
                            "not-assessed": "NOT ASSESSED"}.get(section.status, section.status.upper())
            story.append(Paragraph(
                f'{section.title} -- <font color="{"#2d6a2d" if section.status == "adequate" else "#c47a1e"}">{status_label}</font>',
                S["bold"]
            ))
            story.append(Paragraph(section.content.replace("\n", "<br/>"), S["body"]))
            story.append(Spacer(1, 3*mm))

        if dpia.open_gaps:
            story.append(Paragraph("Open gaps requiring manual review:", S["bold"]))
            for gap in dpia.open_gaps:
                story.append(Paragraph(f"* {gap}", S["body"]))
            story.append(Spacer(1, 3*mm))

    # -- SIGN-OFF -------------------------------------------------------------
    story.append(PageBreak())
    story.append(Paragraph("Sign-Off and Attestation", S["section_head"]))
    story.append(HRFlowable(width=W, thickness=1, color=BLUE, spaceAfter=6))
    story.append(Paragraph(
        "This report was generated by AgentScan on the basis of static configuration analysis. "
        "It does not constitute a legal compliance opinion. Regulated entities must obtain appropriate "
        "legal and technical advice before making compliance attestations to regulators.",
        S["small"]
    ))
    story.append(Spacer(1, 6*mm))

    signoff_data = [
        ["Role", "Name", "Signature", "Date"],
        ["Security Lead / CISO", "", "___________________________", "___________"],
        ["Privacy Officer / DPO", "", "___________________________", "___________"],
        ["Board Representative", "", "___________________________", "___________"],
        ["Compliance Officer", "", "___________________________", "___________"],
    ]
    signoff_table = Table(signoff_data, colWidths=[45*mm, 45*mm, 55*mm, 25*mm])
    signoff_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), BLUE),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
        ("PADDING", (0, 0), (-1, -1), 8),
        ("ROWHEIGHT", (0, 1), (-1, -1), 20),
    ]))
    story.append(signoff_table)
    story.append(Spacer(1, 4*mm))
    story.append(Paragraph(
        f"Generated by AgentScan v0.1.0  -  {date.today().isoformat()}  -  "
        "github.com/sneh2105/agentscan  -  Apache 2.0",
        ParagraphStyle("footer", fontSize=7, textColor=MID_GREY, alignment=TA_CENTER)
    ))

    doc.build(story)
    return output_path
