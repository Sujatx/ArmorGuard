import re
from datetime import datetime
from html import escape as _esc
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_RIGHT
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

_BRAND_DARK  = colors.HexColor("#0f172a")
_BRAND_MID   = colors.HexColor("#1e293b")
_BRAND_LIGHT = colors.HexColor("#f8fafc")
_ACCENT      = colors.HexColor("#6366f1")
_TEXT_MUTED  = colors.HexColor("#64748b")
_TEXT_BODY   = colors.HexColor("#1e293b")
_RED         = colors.HexColor("#dc2626")
_RED_BG      = colors.HexColor("#fff5f5")
_RED_LABEL   = colors.HexColor("#7f1d1d")
_BORDER      = colors.HexColor("#e2e8f0")
_PAGE_W      = 6.45 * inch   # usable width with 0.75 in margins on letter


def _humanize(text: str) -> str:
    """snake_case / error codes → readable Title Case."""
    if not text:
        return "—"
    return " ".join(w.capitalize() for w in text.replace("-", "_").split("_"))


def _no_link(text: str) -> str:
    """Defang URLs (http[://]host) so PDF viewers don't auto-detect them as hyperlinks."""
    if not text:
        return "—"
    return re.sub(r"https?://", lambda m: m.group(0).replace("://", "[://]"), text)


def _risk_color(score: int) -> colors.Color:
    if score >= 75:
        return colors.HexColor("#dc2626")
    if score >= 50:
        return colors.HexColor("#ea580c")
    if score >= 25:
        return colors.HexColor("#d97706")
    return colors.HexColor("#16a34a")


def _p(text: str, style) -> Paragraph:
    return Paragraph(text, style)


def _finding_card(finding, styles) -> KeepTogether:
    sev_color = _SEV_COLOR.get(finding.severity, colors.grey)

    hdr = Table(
        [[f"  {finding.severity.upper()}  ", _esc(finding.title)]],
        colWidths=[0.85 * inch, _PAGE_W - 0.85 * inch],
    )
    hdr.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (0, 0), sev_color),
        ("BACKGROUND",    (1, 0), (1, 0), _BRAND_LIGHT),
        ("TEXTCOLOR",     (0, 0), (0, 0), colors.white),
        ("TEXTCOLOR",     (1, 0), (1, 0), _TEXT_BODY),
        ("FONTNAME",      (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 9),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("BOX",           (0, 0), (-1, -1), 0.5, _BORDER),
        ("LINEAFTER",     (0, 0), (0, 0), 0.5, _BORDER),
    ]))

    lbl = ParagraphStyle("card_lbl", parent=styles["Normal"],
                         fontSize=8.5, fontName="Helvetica-Bold",
                         textColor=_TEXT_MUTED,
                         leftIndent=8, spaceAfter=1, spaceBefore=5)
    body = ParagraphStyle("card_body", parent=styles["Normal"],
                          fontSize=9, textColor=_TEXT_BODY,
                          leftIndent=8, spaceAfter=2)
    ev_style = ParagraphStyle("card_ev", fontName="Courier",
                              fontSize=7.5, leading=11, leftIndent=8,
                              textColor=colors.HexColor("#334155"))

    elems = [
        hdr,
        _p("Description", lbl),
        _p(_esc(finding.description), body),
        _p("Remediation", lbl),
        _p(_esc(finding.remediation), body),
    ]
    if finding.evidence:
        elems.append(_p("Evidence", lbl))
        elems.append(_p(_esc(finding.evidence), ev_style))

    elems.append(Spacer(1, 0.12 * inch))
    return KeepTogether(elems)


def _drift_section(drift: dict, styles) -> list:
    """Two-column label/value table for the policy-block incident."""
    classification = _humanize(drift.get("drift_classification", ""))
    attempted      = _esc(_no_link(drift.get("attempted_action", "—")))
    block_reason   = _esc(_no_link(drift.get("block_reason", "—")))
    error_code     = _humanize(drift.get("error_code", ""))

    hdr_style = ParagraphStyle(
        "drift_hdr", parent=styles["Normal"],
        fontSize=10, fontName="Helvetica-Bold", textColor=colors.white,
    )
    lbl_style = ParagraphStyle(
        "drift_lbl", parent=styles["Normal"],
        fontSize=9, fontName="Helvetica-Bold", textColor=_RED_LABEL,
    )
    val_style = ParagraphStyle(
        "drift_val", parent=styles["Normal"],
        fontSize=9, textColor=_TEXT_BODY,
    )

    COL_LBL = 1.35 * inch
    COL_VAL = _PAGE_W - COL_LBL

    # Red header spanning full width
    hdr_row = Table(
        [[_p("⚠  SECURITY POLICY INCIDENT — Scan Halted", hdr_style)]],
        colWidths=[_PAGE_W],
    )
    hdr_row.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), _RED),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
    ]))

    body_tbl = Table(
        [
            [_p("Classification",   lbl_style), _p(_esc(classification), val_style)],
            [_p("Attempted Action", lbl_style), _p(attempted,            val_style)],
            [_p("Block Reason",     lbl_style), _p(block_reason,         val_style)],
            [_p("Error Code",       lbl_style), _p(_esc(error_code),     val_style)],
        ],
        colWidths=[COL_LBL, COL_VAL],
    )
    body_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), _RED_BG),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING",    (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
        ("LINEBELOW",     (0, 0), (-1, -2), 0.5, _BORDER),
        ("LINEBEFORE",    (1, 0), (1, -1), 0.5, _BORDER),
    ]))

    # Wrap header + body in an outer bordered box
    wrapper = Table(
        [[hdr_row], [body_tbl]],
        colWidths=[_PAGE_W],
    )
    wrapper.setStyle(TableStyle([
        ("BOX",          (0, 0), (-1, -1), 1.5, _RED),
        ("TOPPADDING",   (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 0),
        ("LEFTPADDING",  (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
    ]))
    return [wrapper, Spacer(1, 0.28 * inch)]


def _fix_prompt_page(fix_prompt: str, styles) -> list:
    mono = ParagraphStyle(
        "prompt_line", fontName="Courier", fontSize=8, leading=11,
        backColor=colors.HexColor("#f1f5f9"),
        leftIndent=12, rightIndent=12,
        textColor=_TEXT_BODY,
    )
    lines = [
        _p(_esc(ln) if ln.strip() else "&nbsp;", mono)
        for ln in fix_prompt.split("\n")
    ]
    h2 = ParagraphStyle("fix_h2", parent=styles["Heading2"],
                        fontSize=13, textColor=_BRAND_DARK,
                        spaceBefore=0, spaceAfter=4)
    instr = ParagraphStyle("fix_instr", parent=styles["Normal"],
                           fontSize=9.5, spaceAfter=10, textColor=_TEXT_MUTED)
    return [
        _p("Fix-It Prompt", h2),
        _p(
            "Copy the prompt below and paste it into Cursor, Claude, or GitHub Copilot "
            "to automatically remediate all vulnerabilities found in this scan.",
            instr,
        ),
        Spacer(1, 0.08 * inch),
    ] + lines


def generate_report_pdf(report, drift_event: dict | None = None) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=letter,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
    )
    styles = getSampleStyleSheet()
    story = []

    # ── Branded header ──────────────────────────────────────────────────────
    title_style = ParagraphStyle(
        "rpt_title", parent=styles["Normal"],
        fontSize=20, fontName="Helvetica-Bold", textColor=colors.white,
        leading=26,
    )
    sub_style = ParagraphStyle(
        "rpt_sub", parent=styles["Normal"],
        fontSize=9, textColor=colors.HexColor("#94a3b8"),
        leading=13,
    )
    generated = datetime.utcnow().strftime("%B %d, %Y  %H:%M UTC")

    # Single cell containing a list of flowables so Spacer controls the gap
    hdr_cell = [
        _p("ArmorGuard Security Report", title_style),
        Spacer(1, 6),
        _p(f"Generated  {generated}", sub_style),
    ]
    hdr_tbl = Table([[hdr_cell]], colWidths=[_PAGE_W])
    hdr_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), _BRAND_DARK),
        ("TOPPADDING",    (0, 0), (-1, -1), 16),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 16),
        ("LEFTPADDING",   (0, 0), (-1, -1), 14),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 14),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(hdr_tbl)

    # Thin accent line
    accent = Table([[""]], colWidths=[_PAGE_W], rowHeights=[3])
    accent.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), _ACCENT)]))
    story.append(accent)
    story.append(Spacer(1, 0.2 * inch))

    # ── Scan metadata ───────────────────────────────────────────────────────
    meta_lbl = ParagraphStyle("meta_l", parent=styles["Normal"],
                              fontSize=9, fontName="Helvetica-Bold",
                              textColor=_TEXT_MUTED)
    meta_val = ParagraphStyle("meta_v", parent=styles["Normal"],
                              fontSize=9, textColor=_TEXT_BODY)
    meta_tbl = Table(
        [
            [_p("Target",    meta_lbl), _p(_esc(report.target_url),            meta_val)],
            [_p("Scan Mode", meta_lbl), _p(_esc(report.scan_mode.capitalize()), meta_val)],
        ],
        colWidths=[0.9 * inch, _PAGE_W - 0.9 * inch],
    )
    meta_tbl.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
    ]))
    story.append(meta_tbl)
    story.append(Spacer(1, 0.25 * inch))

    # ── Executive Summary ───────────────────────────────────────────────────
    story.append(_p(
        "Executive Summary",
        ParagraphStyle("sec_h2", parent=styles["Heading2"],
                       fontSize=13, textColor=_BRAND_DARK,
                       spaceBefore=0, spaceAfter=10),
    ))

    bys   = report.summary.by_severity
    score = report.summary.risk_score
    sc    = _risk_color(score)

    # Risk score block — flat single table, no nested tables
    risk_lbl = ParagraphStyle("rl", parent=styles["Normal"],
                              fontSize=8, textColor=_TEXT_MUTED,
                              fontName="Helvetica-Bold", alignment=TA_CENTER)
    risk_num = ParagraphStyle("rn", parent=styles["Normal"],
                              fontSize=38, fontName="Helvetica-Bold",
                              textColor=sc, alignment=TA_CENTER, leading=44)
    risk_sub = ParagraphStyle("rs", parent=styles["Normal"],
                              fontSize=8, textColor=_TEXT_MUTED,
                              alignment=TA_CENTER)

    score_tbl = Table(
        [
            [_p("",          risk_lbl)],   # colored accent strip row
            [_p("RISK SCORE", risk_lbl)],
            [_p(str(score),   risk_num)],
            [_p("/ 100",      risk_sub)],
        ],
        colWidths=[1.65 * inch],
        rowHeights=[5, None, None, None],
    )
    score_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), sc),           # colored top strip
        ("BACKGROUND",    (0, 1), (-1, -1), _BRAND_LIGHT),
        ("BOX",           (0, 0), (-1, -1), 1, _BORDER),
        ("TOPPADDING",    (0, 1), (-1, 1), 8),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 2),
        ("TOPPADDING",    (0, 2), (-1, 2), 0),
        ("BOTTOMPADDING", (0, 2), (-1, 2), 0),
        ("TOPPADDING",    (0, 3), (-1, 3), 2),
        ("BOTTOMPADDING", (0, 3), (-1, 3), 10),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
    ]))

    # Severity breakdown table
    sev_hdr = ParagraphStyle("sh", parent=styles["Normal"],
                             fontSize=9, fontName="Helvetica-Bold",
                             textColor=colors.white, alignment=TA_CENTER)
    sev_val = ParagraphStyle("sv", parent=styles["Normal"],
                             fontSize=9, fontName="Helvetica-Bold",
                             textColor=colors.white, alignment=TA_CENTER)
    sev_data = [
        [_p("Severity", sev_hdr), _p("Count", sev_hdr)],
        *[
            [_p(name, sev_val), _p(str(cnt), sev_val)]
            for name, cnt in [
                ("Critical", bys.Critical), ("High", bys.High),
                ("Medium", bys.Medium),     ("Low",  bys.Low),
            ]
        ],
    ]
    sev_tbl = Table(sev_data, colWidths=[1.5 * inch, 0.8 * inch])
    sev_cmds = [
        ("BACKGROUND",    (0, 0), (-1, 0), _BRAND_MID),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("GRID",          (0, 0), (-1, -1), 0.5, colors.white),
    ]
    for i, name in enumerate(["Critical", "High", "Medium", "Low"], start=1):
        sev_cmds.append(("BACKGROUND", (0, i), (-1, i), _SEV_COLOR[name]))
    sev_tbl.setStyle(TableStyle(sev_cmds))

    # Place both side-by-side
    summary_row = Table(
        [[score_tbl, sev_tbl]],
        colWidths=[1.95 * inch, 2.5 * inch],
    )
    summary_row.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 16),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(summary_row)
    story.append(Spacer(1, 0.3 * inch))

    # ── Intent-Drift Incident ────────────────────────────────────────────────
    if drift_event:
        story.extend(_drift_section(drift_event, styles))

    # ── Fix-It Prompt ────────────────────────────────────────────────────────
    if report.fix_prompt:
        story.extend(_fix_prompt_page(report.fix_prompt, styles))

    # ── Findings ─────────────────────────────────────────────────────────────
    if report.findings:
        story.append(PageBreak())
        story.append(_p(
            "Findings",
            ParagraphStyle("find_h2", parent=styles["Heading2"],
                           fontSize=13, textColor=_BRAND_DARK,
                           spaceBefore=0, spaceAfter=8),
        ))
        for f in sorted(report.findings, key=lambda f: _SEV_ORDER.index(f.severity)):
            story.append(_finding_card(f, styles))
    else:
        story.append(_p("No findings recorded.", styles["Normal"]))

    doc.build(story)
    return buffer.getvalue()
