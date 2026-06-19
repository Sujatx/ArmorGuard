from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

_SEVERITY_COLORS = {
    "Critical": colors.HexColor("#dc2626"),
    "High":     colors.HexColor("#ea580c"),
    "Medium":   colors.HexColor("#d97706"),
    "Low":      colors.HexColor("#16a34a"),
}


def generate_report_pdf(report) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter,
                            topMargin=0.75 * inch, bottomMargin=0.75 * inch)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph(
        "ArmorGuard Security Report",
        ParagraphStyle("rpt_title", parent=styles["Title"], fontSize=20, spaceAfter=6),
    ))
    story.append(Paragraph(f"<b>Target:</b> {report.target_url}", styles["Normal"]))
    story.append(Paragraph(f"<b>Scan Mode:</b> {report.scan_mode}", styles["Normal"]))
    story.append(Paragraph(f"<b>Scan ID:</b> {report.scan_id}", styles["Normal"]))
    story.append(Spacer(1, 0.2 * inch))

    story.append(Paragraph("Risk Summary", styles["Heading2"]))
    bys = report.summary.by_severity
    summary_table = Table(
        [
            ["Risk Score", "Total Findings", "Critical", "High", "Medium", "Low"],
            [report.summary.risk_score, report.summary.total_findings,
             bys.Critical, bys.High, bys.Medium, bys.Low],
        ],
        colWidths=[1.1 * inch] * 6,
    )
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ALIGN",      (0, 0), (-1, -1), "CENTER"),
        ("GRID",       (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.2 * inch))

    story.append(Paragraph("Findings", styles["Heading2"]))
    for finding in report.findings:
        sev_color = _SEVERITY_COLORS.get(finding.severity, colors.grey)
        story.append(Paragraph(
            f"[{finding.severity}] {finding.title}",
            ParagraphStyle(f"sev_{finding.severity}", parent=styles["Normal"],
                           textColor=sev_color, fontName="Helvetica-Bold", fontSize=10),
        ))
        story.append(Paragraph(f"<b>Description:</b> {finding.description}", styles["Normal"]))
        story.append(Paragraph(f"<b>Remediation:</b> {finding.remediation}", styles["Normal"]))
        if finding.evidence:
            story.append(Paragraph(f"<b>Evidence:</b> {finding.evidence}", styles["Normal"]))
        story.append(Spacer(1, 0.15 * inch))

    doc.build(story)
    return buffer.getvalue()
