from datetime import datetime
from html import escape as _esc
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    KeepTogether, PageBreak, Paragraph,
    SimpleDocTemplate, Spacer, Table, TableStyle,
)

_SEV_COLOR = {
    "Critical": colors.HexColor("#dc2626"),
    "High":     colors.HexColor("#ea580c"),
    "Medium":   colors.HexColor("#d97706"),
    "Low":      colors.HexColor("#16a34a"),
}
_SEV_ORDER = ["Critical", "High", "Medium", "Low"]


def _finding_card(finding, styles) -> KeepTogether:
    sev_color = _SEV_COLOR.get(finding.severity, colors.grey)

    # Two-cell header: colored severity badge | title
    header = Table(
        [[f"  {finding.severity}  ", _esc(finding.title)]],
        colWidths=[0.9 * inch, 5.55 * inch],
    )
    header.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (0, 0), sev_color),
        ("BACKGROUND",    (1, 0), (1, 0), colors.HexColor("#f8fafc")),
        ("TEXTCOLOR",     (0, 0), (0, 0), colors.white),
        ("TEXTCOLOR",     (1, 0), (1, 0), colors.HexColor("#0f172a")),
        ("FONTNAME",      (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 9),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("BOX",           (0, 0), (-1, -1), 1, sev_color),
    ]))

    label = ParagraphStyle("card_lbl", parent=styles["Normal"],
                           fontSize=9, fontName="Helvetica-Bold",
                           leftIndent=8, spaceAfter=2, spaceBefore=4)
    body = ParagraphStyle("card_body", parent=styles["Normal"],
                          fontSize=9, leftIndent=8, spaceAfter=2)

    elems = [
        header,
        Paragraph("Description", label),
        Paragraph(_esc(finding.description), body),
        Paragraph("Remediation", label),
        Paragraph(_esc(finding.remediation), body),
    ]

    if finding.evidence:
        elems.append(Paragraph("Evidence", label))
        # Preformatted avoids XML parsing issues in raw tool output
        ev_style = ParagraphStyle("card_ev", fontName="Courier",
                                  fontSize=7.5, leading=11, leftIndent=8)
        elems.append(Paragraph(_esc(finding.evidence), ev_style))

    elems.append(Spacer(1, 0.15 * inch))
    return KeepTogether(elems)


def _fix_prompt_page(fix_prompt: str, styles) -> list:
    # Render each line as a separate Paragraph so content can flow across pages.
    # A single Preformatted/Table block cannot split across pages in ReportLab.
    mono = ParagraphStyle(
        "prompt_line", fontName="Courier", fontSize=8, leading=11,
        backColor=colors.HexColor("#f1f5f9"),
        leftIndent=12, rightIndent=12, spaceAfter=0, spaceBefore=0,
    )
    line_paras = []
    for raw_line in fix_prompt.split("\n"):
        # Paragraph needs HTML-safe text; blank lines need a non-empty string.
        line_paras.append(Paragraph(_esc(raw_line) if raw_line.strip() else "&nbsp;", mono))

    instr = ParagraphStyle("fixpage_instr", parent=styles["Normal"],
                           fontSize=10, spaceAfter=10,
                           textColor=colors.HexColor("#475569"))
    return [
        Paragraph(
            "Fix-It Prompt",
            ParagraphStyle("fixpage_h1", parent=styles["Heading1"], fontSize=16, spaceAfter=6),
        ),
        Paragraph(
            "Copy the prompt below and paste it into Cursor, Claude, or GitHub Copilot "
            "to automatically fix all vulnerabilities found in this scan.",
            instr,
        ),
        Spacer(1, 0.1 * inch),
    ] + line_paras


def generate_report_pdf(report) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=letter,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
    )
    styles = getSampleStyleSheet()
    story = []

    # --- Header ---
    story.append(Paragraph(
        "ArmorGuard Security Report",
        ParagraphStyle("rpt_title", parent=styles["Title"], fontSize=22, spaceAfter=4),
    ))
    generated = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    meta = ParagraphStyle("rpt_meta", parent=styles["Normal"], fontSize=9,
                          textColor=colors.HexColor("#475569"), spaceAfter=2)
    story.append(Paragraph(f"<b>Target:</b> {_esc(report.target_url)}", meta))
    story.append(Paragraph(f"<b>Scan Mode:</b> {_esc(report.scan_mode)}", meta))
    story.append(Paragraph(f"<b>Scan ID:</b> {_esc(report.scan_id)}", meta))
    story.append(Paragraph(f"<b>Generated:</b> {generated}", meta))
    story.append(Spacer(1, 0.2 * inch))

    # --- Executive Summary ---
    story.append(Paragraph("Executive Summary", styles["Heading2"]))

    bys = report.summary.by_severity
    sev_rows = [
        ("Critical", bys.Critical),
        ("High",     bys.High),
        ("Medium",   bys.Medium),
        ("Low",      bys.Low),
    ]

    # Risk score on the left, severity breakdown on the right
    score_style = ParagraphStyle("score_num", parent=styles["Normal"],
                                 fontSize=32, fontName="Helvetica-Bold",
                                 alignment=1, textColor=colors.HexColor("#0f172a"))
    score_lbl = ParagraphStyle("score_lbl", parent=styles["Normal"],
                                fontSize=8, alignment=1,
                                textColor=colors.HexColor("#64748b"))

    score_block = Table(
        [
            [Paragraph(str(report.summary.risk_score), score_style)],
            [Paragraph("RISK SCORE / 100", score_lbl)],
            [Paragraph(f"{report.summary.total_findings} finding(s)", score_lbl)],
        ],
        colWidths=[1.6 * inch],
        rowHeights=[48, 14, 14],
    )
    score_block.setStyle(TableStyle([
        ("BOX",           (0, 0), (-1, -1), 1.5, colors.HexColor("#1e293b")),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))

    sev_data = [["Severity", "Count"]]
    for name, count in sev_rows:
        sev_data.append([name, str(count)])

    sev_table = Table(sev_data, colWidths=[1.4 * inch, 0.8 * inch])
    sev_cmds = [
        ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 9),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("GRID",          (0, 0), (-1, -1), 0.5, colors.white),
    ]
    for row_i, (name, _) in enumerate(sev_rows, start=1):
        c = _SEV_COLOR[name]
        sev_cmds += [
            ("BACKGROUND", (0, row_i), (-1, row_i), c),
            ("TEXTCOLOR",  (0, row_i), (-1, row_i), colors.white),
            ("FONTNAME",   (0, row_i), (-1, row_i), "Helvetica-Bold"),
        ]
    sev_table.setStyle(TableStyle(sev_cmds))

    summary_layout = Table(
        [[score_block, sev_table]],
        colWidths=[1.9 * inch, 2.5 * inch],
    )
    summary_layout.setStyle(TableStyle([
        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING",  (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 16),
    ]))
    story.append(summary_layout)
    story.append(Spacer(1, 0.3 * inch))

    # --- Fix-It Prompt (top of report, before findings) ---
    if report.fix_prompt:
        story.extend(_fix_prompt_page(report.fix_prompt, styles))

    # --- Findings ---
    if report.findings:
        story.append(PageBreak())
        story.append(Paragraph("Findings", styles["Heading2"]))
        story.append(Spacer(1, 0.1 * inch))
        sorted_findings = sorted(
            report.findings,
            key=lambda f: _SEV_ORDER.index(f.severity),
        )
        for f in sorted_findings:
            story.append(_finding_card(f, styles))
    else:
        story.append(Paragraph("No findings recorded.", styles["Normal"]))

    doc.build(story)
    return buffer.getvalue()
