import re
from datetime import datetime
from html import escape as _esc
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
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
_ACCENT_SOFT = colors.HexColor("#eef2ff")
_TEXT_MUTED  = colors.HexColor("#64748b")
_TEXT_BODY   = colors.HexColor("#1e293b")
_TEXT_INV    = colors.HexColor("#94a3b8")
_RED         = colors.HexColor("#dc2626")
_RED_BG      = colors.HexColor("#fff5f5")
_RED_LABEL   = colors.HexColor("#7f1d1d")
_BORDER      = colors.HexColor("#e2e8f0")
_GREEN       = colors.HexColor("#16a34a")
_GREEN_BG    = colors.HexColor("#ecfdf5")
_AMBER       = colors.HexColor("#d97706")
_AMBER_BG    = colors.HexColor("#fffbeb")
_MONO_BG     = colors.HexColor("#f1f5f9")
_PAGE_W      = 6.45 * inch   # usable width with 0.75 in margins on letter
_CARD_PAD    = 12            # left/right padding inside a finding card (points)
_CARD_W      = _PAGE_W - 2 * _CARD_PAD   # usable width for tables inside a card


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


def _risk_posture(score: int) -> str:
    if score >= 75:
        return "Critical risk posture"
    if score >= 50:
        return "High risk posture"
    if score >= 25:
        return "Moderate risk posture"
    return "Low risk posture"


def _p(text: str, style) -> Paragraph:
    return Paragraph(text, style)


def _get(obj, name, default=None):
    """Defensive attribute access that works whether the field exists or not."""
    val = getattr(obj, name, default)
    return val if val else default


# ── Shared paragraph styles ──────────────────────────────────────────────────

def _styles(base):
    s = {}
    s["section_h"] = ParagraphStyle(
        "section_h", parent=base["Heading2"],
        fontSize=15, fontName="Helvetica-Bold", textColor=_BRAND_DARK,
        spaceBefore=0, spaceAfter=3, leading=19,
    )
    s["section_kicker"] = ParagraphStyle(
        "section_kicker", parent=base["Normal"],
        fontSize=8, fontName="Helvetica-Bold", textColor=_ACCENT,
        spaceAfter=10, leading=11, tracking=1,
    )
    s["body"] = ParagraphStyle(
        "body", parent=base["Normal"],
        fontSize=9.5, leading=15, textColor=_TEXT_BODY, spaceAfter=8,
        alignment=TA_LEFT,
    )
    s["muted"] = ParagraphStyle(
        "muted", parent=base["Normal"],
        fontSize=9, leading=14, textColor=_TEXT_MUTED, spaceAfter=6,
    )
    return s


def _section_heading(kicker: str, title: str, s) -> list:
    """Consistent kicker + heading + accent rule."""
    rule = Table([[""]], colWidths=[0.5 * inch], rowHeights=[2.5])
    rule.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), _ACCENT)]))
    return [
        _p(kicker.upper(), s["section_kicker"]),
        _p(_esc(title), s["section_h"]),
        rule,
        Spacer(1, 0.16 * inch),
    ]


# ── Cover page ───────────────────────────────────────────────────────────────

def _cover_page(report, generated: str) -> list:
    brand = ParagraphStyle(
        "cover_brand", fontSize=46, fontName="Helvetica-Bold",
        textColor=colors.white, alignment=TA_LEFT, leading=50,
    )
    tagline = ParagraphStyle(
        "cover_tag", fontSize=10, fontName="Helvetica", textColor=_ACCENT,
        alignment=TA_LEFT, leading=14, spaceBefore=6,
    )
    rtype = ParagraphStyle(
        "cover_rtype", fontSize=17, fontName="Helvetica-Bold",
        textColor=colors.white, alignment=TA_LEFT, leading=22,
    )
    rtype_sub = ParagraphStyle(
        "cover_rtype_sub", fontSize=10, fontName="Helvetica",
        textColor=_TEXT_INV, alignment=TA_LEFT, leading=14,
    )
    meta_lbl = ParagraphStyle(
        "cover_meta_l", fontSize=8, fontName="Helvetica-Bold",
        textColor=_ACCENT, alignment=TA_LEFT, leading=12,
    )
    meta_val = ParagraphStyle(
        "cover_meta_v", fontSize=10.5, fontName="Helvetica",
        textColor=colors.white, alignment=TA_LEFT, leading=15,
    )
    conf = ParagraphStyle(
        "cover_conf", fontSize=8, fontName="Helvetica-Bold",
        textColor=_TEXT_INV, alignment=TA_LEFT, leading=13,
    )

    # Top brand block
    brand_block = [
        _p("ArmorGuard", brand),
        _p("Autonomous Offensive Security Platform", tagline),
    ]

    # Report-type band
    type_block = [
        _p("Penetration Test Report", rtype),
        _p("Security Assessment &amp; Confirmed-Vulnerability Analysis", rtype_sub),
    ]

    # Metadata rows
    def _row(label, value):
        return [_p(label.upper(), meta_lbl), _p(_esc(_no_link(value)), meta_val)]

    meta = Table(
        [
            _row("Target", str(report.target_url)),
            _row("Scan Mode", str(report.scan_mode).capitalize()),
            _row("Scan ID", str(report.scan_id)),
            _row("Generated", generated),
        ],
        colWidths=[1.15 * inch, _PAGE_W - 1.15 * inch],
    )
    meta.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING",    (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ("LINEBELOW",     (0, 0), (-1, -2), 0.5, colors.HexColor("#334155")),
    ]))

    conf_block = Table(
        [[_p(
            "CONFIDENTIAL — prepared for authorized recipient only. This document contains "
            "sensitive security information. Unauthorized disclosure, distribution, or "
            "reproduction is strictly prohibited.", conf)]],
        colWidths=[_PAGE_W],
    )
    conf_block.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#1e293b")),
        ("BOX",           (0, 0), (-1, -1), 0.75, _ACCENT),
        ("TOPPADDING",    (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ("LEFTPADDING",   (0, 0), (-1, -1), 14),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 14),
    ]))

    # Assemble the full-bleed dark cover as one tall table cell
    inner = [
        Spacer(1, 0.55 * inch),
        *brand_block,
        Spacer(1, 0.16 * inch),
    ]
    # thin accent rule under brand
    accent_rule = Table([[""]], colWidths=[1.4 * inch], rowHeights=[3])
    accent_rule.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), _ACCENT)]))
    inner.append(accent_rule)
    inner += [
        Spacer(1, 1.7 * inch),
        *type_block,
        Spacer(1, 0.5 * inch),
        meta,
        Spacer(1, 0.9 * inch),
        conf_block,
        Spacer(1, 0.4 * inch),
    ]

    cover = Table([[inner]], colWidths=[_PAGE_W + 1.5 * inch])
    cover.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), _BRAND_DARK),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0.75 * inch),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0.75 * inch),
    ]))

    # Wrap so the dark panel bleeds to the page margins
    wrap = Table([[cover]], colWidths=[_PAGE_W])
    wrap.setStyle(TableStyle([
        ("LEFTPADDING",   (0, 0), (-1, -1), -0.75 * inch),
        ("RIGHTPADDING",  (0, 0), (-1, -1), -0.75 * inch),
        ("TOPPADDING",    (0, 0), (-1, -1), -0.75 * inch),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]))
    return [wrap, PageBreak()]


# ── Methodology & Scope ──────────────────────────────────────────────────────

def _methodology_page(report, generated: str, s) -> list:
    elems = _section_heading("Assessment Overview", "Methodology & Scope", s)

    elems.append(_p(
        "ArmorGuard performed an automated, intent-driven security assessment of the target "
        "system below. The engagement follows a closed-loop offensive methodology: passive and "
        "active <b>fingerprinting</b> of the attack surface, LLM-driven <b>tool selection</b> "
        "constrained to fingerprint-eligible techniques, active <b>exploitation</b> of candidate "
        "weaknesses, and <b>proof-of-concept confirmation</b> of each candidate before it is "
        "admitted to this report.",
        s["body"],
    ))
    elems.append(_p(
        "<b>Only findings that were actively confirmed via proof-of-concept are reported.</b> "
        "Candidate weaknesses that could not be independently proven exploitable are demoted and "
        "excluded. This confirmed-only stance is deliberate: it delivers a zero-false-positive "
        "result set that a remediation team can act on without triage overhead.",
        s["body"],
    ))
    elems.append(Spacer(1, 0.12 * inch))

    # Scope table
    lbl = ParagraphStyle("scope_l", parent=s["body"],
                         fontSize=9, fontName="Helvetica-Bold",
                         textColor=_TEXT_MUTED, spaceAfter=0, leading=13)
    val = ParagraphStyle("scope_v", parent=s["body"],
                         fontSize=9.5, textColor=_TEXT_BODY, spaceAfter=0, leading=13)

    def _row(k, v):
        return [_p(k.upper(), lbl), _p(_esc(_no_link(v)), val)]

    scope = Table(
        [
            [_p("SCOPE OF ASSESSMENT", ParagraphStyle(
                "scope_hdr", fontSize=9, fontName="Helvetica-Bold",
                textColor=colors.white)), ""],
            _row("Target", str(report.target_url)),
            _row("Scan Mode", str(report.scan_mode).capitalize()),
            _row("Scan ID", str(report.scan_id)),
            _row("Assessment Date", generated),
        ],
        colWidths=[1.6 * inch, _PAGE_W - 1.6 * inch],
    )
    scope.setStyle(TableStyle([
        ("SPAN",          (0, 0), (1, 0)),
        ("BACKGROUND",    (0, 0), (-1, 0), _BRAND_MID),
        ("BACKGROUND",    (0, 1), (0, -1), _BRAND_LIGHT),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING",   (0, 0), (-1, -1), 12),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 12),
        ("BOX",           (0, 0), (-1, -1), 0.5, _BORDER),
        ("LINEBELOW",     (0, 1), (-1, -2), 0.5, _BORDER),
        ("LINEAFTER",     (0, 1), (0, -1), 0.5, _BORDER),
    ]))
    elems.append(scope)
    elems.append(PageBreak())
    return elems


# ── Executive Summary ────────────────────────────────────────────────────────

def _exec_summary(report, s) -> list:
    elems = _section_heading("Risk Overview", "Executive Summary", s)

    exec_prose = _get(report, "executive_summary")
    if exec_prose:
        elems.append(_p(_esc(str(exec_prose)), s["body"]))
        elems.append(Spacer(1, 0.06 * inch))

    bys   = report.summary.by_severity
    score = int(report.summary.risk_score)
    total = int(getattr(report.summary, "total_findings", 0) or 0)
    sc    = _risk_color(score)

    # Risk-score card
    risk_lbl = ParagraphStyle("rl", parent=s["body"], fontSize=8,
                              textColor=_TEXT_MUTED, fontName="Helvetica-Bold",
                              alignment=TA_CENTER, spaceAfter=0)
    risk_num = ParagraphStyle("rn", parent=s["body"], fontSize=40,
                              fontName="Helvetica-Bold", textColor=sc,
                              alignment=TA_CENTER, leading=44, spaceAfter=0)
    risk_sub = ParagraphStyle("rs", parent=s["body"], fontSize=8,
                              textColor=_TEXT_MUTED, alignment=TA_CENTER,
                              spaceAfter=0)
    posture_st = ParagraphStyle("rp", parent=s["body"], fontSize=8.5,
                                fontName="Helvetica-Bold", textColor=sc,
                                alignment=TA_CENTER, spaceAfter=0, leading=11)

    score_tbl = Table(
        [
            [_p("", risk_lbl)],
            [_p("RISK SCORE", risk_lbl)],
            [_p(str(score), risk_num)],
            [_p("/ 100", risk_sub)],
            [_p(_risk_posture(score).upper(), posture_st)],
        ],
        colWidths=[1.85 * inch],
        rowHeights=[5, None, None, None, None],
    )
    score_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), sc),
        ("BACKGROUND",    (0, 1), (-1, -1), _BRAND_LIGHT),
        ("BOX",           (0, 0), (-1, -1), 1, _BORDER),
        ("TOPPADDING",    (0, 1), (-1, 1), 8),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 2),
        ("TOPPADDING",    (0, 2), (-1, 2), 0),
        ("BOTTOMPADDING", (0, 2), (-1, 2), 0),
        ("TOPPADDING",    (0, 3), (-1, 3), 2),
        ("BOTTOMPADDING", (0, 3), (-1, 3), 6),
        ("TOPPADDING",    (0, 4), (-1, 4), 0),
        ("BOTTOMPADDING", (0, 4), (-1, 4), 10),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
    ]))

    # Severity breakdown
    sev_hdr = ParagraphStyle("sh", parent=s["body"], fontSize=9,
                             fontName="Helvetica-Bold", textColor=colors.white,
                             alignment=TA_CENTER, spaceAfter=0)
    sev_name = ParagraphStyle("sn", parent=s["body"], fontSize=9,
                              fontName="Helvetica-Bold", textColor=colors.white,
                              alignment=TA_LEFT, spaceAfter=0)
    sev_cnt = ParagraphStyle("scnt", parent=s["body"], fontSize=11,
                             fontName="Helvetica-Bold", textColor=colors.white,
                             alignment=TA_CENTER, spaceAfter=0)

    sev_data = [
        [_p("SEVERITY", sev_hdr), _p("COUNT", sev_hdr)],
        *[
            [_p(name, sev_name), _p(str(cnt), sev_cnt)]
            for name, cnt in [
                ("Critical", bys.Critical), ("High", bys.High),
                ("Medium", bys.Medium),     ("Low",  bys.Low),
            ]
        ],
        [_p("TOTAL", sev_name), _p(str(total), sev_cnt)],
    ]
    sev_tbl = Table(sev_data, colWidths=[1.65 * inch, 0.85 * inch])
    sev_cmds = [
        ("BACKGROUND",    (0, 0), (-1, 0), _BRAND_MID),
        ("BACKGROUND",    (0, -1), (-1, -1), _BRAND_DARK),
        ("TOPPADDING",    (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING",   (0, 0), (0, -1), 12),
        ("GRID",          (0, 0), (-1, -1), 0.5, colors.white),
    ]
    for i, name in enumerate(["Critical", "High", "Medium", "Low"], start=1):
        sev_cmds.append(("BACKGROUND", (0, i), (-1, i), _SEV_COLOR[name]))
    sev_tbl.setStyle(TableStyle(sev_cmds))

    summary_row = Table(
        [[score_tbl, sev_tbl]],
        colWidths=[2.15 * inch, 2.7 * inch],
    )
    summary_row.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (0, 0), 18),
        ("RIGHTPADDING",  (1, 0), (1, 0), 0),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    elems.append(summary_row)
    elems.append(Spacer(1, 0.14 * inch))

    # One-line posture statement
    posture_line = ParagraphStyle(
        "posture_line", parent=s["body"], fontSize=9.5, leading=14,
        textColor=_TEXT_BODY, spaceAfter=0,
    )
    verdict = (
        f"Based on a composite risk score of <b>{score}/100</b>, the target presents a "
        f"<b>{_risk_posture(score).lower()}</b>. A total of <b>{total}</b> confirmed "
        f"finding{'s' if total != 1 else ''} {'were' if total != 1 else 'was'} validated "
        f"during this assessment."
    )
    banner = Table([[_p(verdict, posture_line)]], colWidths=[_PAGE_W])
    banner.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), _ACCENT_SOFT),
        ("LINEBEFORE",    (0, 0), (0, -1), 3, _ACCENT),
        ("TOPPADDING",    (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING",   (0, 0), (-1, -1), 14),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 14),
    ]))
    elems.append(banner)
    elems.append(Spacer(1, 0.28 * inch))
    return elems


# ── Intent-Drift Incident (preserved, restyled) ──────────────────────────────

def _drift_section(drift: dict, styles) -> list:
    """Two-column label/value table for the policy-block incident."""
    classification = _humanize(drift.get("drift_classification", ""))
    attempted      = _esc(_no_link(drift.get("attempted_action", "—")))
    block_reason   = _esc(_no_link(drift.get("block_reason", "—")))
    error_code     = _humanize(drift.get("error_code", ""))

    hdr_style = ParagraphStyle(
        "drift_hdr", parent=styles["Normal"],
        fontSize=10.5, fontName="Helvetica-Bold", textColor=colors.white,
    )
    hdr_sub = ParagraphStyle(
        "drift_hdr_sub", parent=styles["Normal"],
        fontSize=8, fontName="Helvetica", textColor=colors.HexColor("#fecaca"),
    )
    lbl_style = ParagraphStyle(
        "drift_lbl", parent=styles["Normal"],
        fontSize=9, fontName="Helvetica-Bold", textColor=_RED_LABEL,
    )
    val_style = ParagraphStyle(
        "drift_val", parent=styles["Normal"],
        fontSize=9, textColor=_TEXT_BODY, leading=13,
    )

    COL_LBL = 1.5 * inch
    COL_VAL = _PAGE_W - COL_LBL

    # Red header spanning full width
    hdr_row = Table(
        [[_p("SECURITY POLICY INCIDENT — Scan Halted", hdr_style)],
         [_p("ArmorIQ governance intercepted an out-of-policy action mid-scan.", hdr_sub)]],
        colWidths=[_PAGE_W],
    )
    hdr_row.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), _RED),
        ("TOPPADDING",    (0, 0), (-1, 0), 9),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 1),
        ("TOPPADDING",    (0, 1), (-1, 1), 0),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 9),
        ("LEFTPADDING",   (0, 0), (-1, -1), 12),
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
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING",   (0, 0), (-1, -1), 12),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 12),
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


# ── Finding card (enriched, degrades gracefully) ─────────────────────────────

def _normalize_compliance(comp):
    """Accept list[str] or dict → flat list of display strings."""
    if not comp:
        return []
    if isinstance(comp, dict):
        out = []
        for k, v in comp.items():
            if isinstance(v, (list, tuple)):
                out.extend(f"{k}: {i}" for i in v)
            elif v:
                out.append(f"{k}: {v}")
            else:
                out.append(str(k))
        return out
    if isinstance(comp, (list, tuple)):
        return [str(c) for c in comp if c]
    return [str(comp)]


def _normalize_asset(asset):
    """Accept str or dict → readable string."""
    if not asset:
        return None
    if isinstance(asset, dict):
        parts = []
        for key in ("method", "url", "endpoint", "param", "parameter"):
            if asset.get(key):
                label = "Parameter" if key in ("param", "parameter") else key.capitalize()
                parts.append(f"{label}: {asset[key]}")
        if not parts:
            parts = [f"{k}: {v}" for k, v in asset.items() if v]
        return "  •  ".join(parts)
    return str(asset)


def _confidence_badge(text: str):
    is_confirmed = "confirm" in text.lower()
    fg = _GREEN if is_confirmed else _AMBER
    bg = _GREEN_BG if is_confirmed else _AMBER_BG
    st = ParagraphStyle("conf_badge", fontSize=8, fontName="Helvetica-Bold",
                        textColor=fg, alignment=TA_CENTER, leading=10)
    tbl = Table([[_p(_esc(text.upper()), st)]], colWidths=[1.9 * inch])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), bg),
        ("BOX",           (0, 0), (-1, -1), 0.75, fg),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
    ]))
    return tbl


def _meta_strip(finding, styles):
    """Compact scannable key/value grid for enriched metadata. Returns None if empty."""
    lbl = ParagraphStyle("ms_lbl", parent=styles["Normal"], fontSize=7,
                         fontName="Helvetica-Bold", textColor=_TEXT_MUTED,
                         leading=9)
    val = ParagraphStyle("ms_val", parent=styles["Normal"], fontSize=8.5,
                         fontName="Helvetica-Bold", textColor=_TEXT_BODY,
                         leading=11)

    cells = []
    cvss = _get(finding, "cvss_score")
    if cvss is not None:
        vec = _get(finding, "cvss_vector")
        cvss_val = f"{cvss}"
        if vec:
            cvss_val += f'<br/><font size="6" color="#64748b">{_esc(str(vec))}</font>'
        cells.append(("CVSS", cvss_val))
    if _get(finding, "cwe_id"):
        cells.append(("CWE", _esc(str(finding.cwe_id))))
    if _get(finding, "owasp_category"):
        cells.append(("OWASP", _esc(str(finding.owasp_category))))
    if _get(finding, "attack_technique_id"):
        cells.append(("MITRE ATT&amp;CK", _esc(str(finding.attack_technique_id))))

    if not cells:
        return None

    # Build a grid: label row over value row, up to 4 columns
    label_row = [_p(k, lbl) for k, _ in cells]
    value_row = [_p(v, val) for _, v in cells]
    n = len(cells)
    col_w = _CARD_W / max(n, 1)
    tbl = Table([label_row, value_row], colWidths=[col_w] * n)
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), _BRAND_LIGHT),
        ("BOX",           (0, 0), (-1, -1), 0.5, _BORDER),
        ("INNERGRID",     (0, 0), (-1, -1), 0.5, _BORDER),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, 0), 6),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 0),
        ("TOPPADDING",    (0, 1), (-1, 1), 1),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
    ]))
    return tbl


def _finding_card(finding, styles, index=None) -> KeepTogether:
    sev = getattr(finding, "severity", "Low")
    sev_color = _SEV_COLOR.get(sev, colors.grey)

    num = f"{index:02d}  " if index is not None else ""
    hdr = Table(
        [[f"  {sev.upper()}  ", f"{num}{_esc(getattr(finding, 'title', 'Untitled'))}"]],
        colWidths=[0.9 * inch, _CARD_W - 0.9 * inch],
    )
    hdr.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (0, 0), sev_color),
        ("BACKGROUND",    (1, 0), (1, 0), _BRAND_DARK),
        ("TEXTCOLOR",     (0, 0), (0, 0), colors.white),
        ("TEXTCOLOR",     (1, 0), (1, 0), colors.white),
        ("FONTNAME",      (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (0, 0), 8.5),
        ("FONTSIZE",      (1, 0), (1, 0), 10),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("ALIGN",         (0, 0), (0, 0), "CENTER"),
    ]))

    lbl = ParagraphStyle("card_lbl", parent=styles["Normal"],
                         fontSize=8, fontName="Helvetica-Bold",
                         textColor=_ACCENT, leftIndent=0, spaceAfter=2,
                         spaceBefore=8, leading=10)
    body = ParagraphStyle("card_body", parent=styles["Normal"],
                          fontSize=9, textColor=_TEXT_BODY, leading=13,
                          leftIndent=0, spaceAfter=2)
    mono = ParagraphStyle("card_mono", fontName="Courier", fontSize=7.5,
                          leading=11, leftIndent=8, rightIndent=8,
                          textColor=colors.HexColor("#334155"),
                          backColor=_MONO_BG, spaceBefore=1, spaceAfter=1)

    # Inner content padded via a single-column wrapper table
    inner = [hdr]

    # Confidence badge (own row, right under header)
    conf = _get(finding, "confidence")
    if conf:
        inner.append(Spacer(1, 6))
        inner.append(_confidence_badge(str(conf)))

    # Metadata strip
    strip = _meta_strip(finding, styles)
    if strip is not None:
        inner.append(Spacer(1, 8))
        inner.append(strip)

    def _add(label, value, style=body, mono_lines=False):
        if not value:
            return
        inner.append(_p(label, lbl))
        if mono_lines:
            for ln in str(value).split("\n"):
                inner.append(_p(_esc(ln) if ln.strip() else "&nbsp;", mono))
        else:
            inner.append(_p(_esc(str(value)), style))

    _add("DESCRIPTION", getattr(finding, "description", None))
    _add("BUSINESS IMPACT", _get(finding, "business_impact"))

    asset = _normalize_asset(_get(finding, "affected_asset"))
    if asset:
        inner.append(_p("AFFECTED ASSET", lbl))
        inner.append(_p(_esc(_no_link(asset)), body))

    _add("REPRODUCTION", _get(finding, "reproduction"), mono_lines=True)
    _add("REMEDIATION", getattr(finding, "remediation", None))

    ev = getattr(finding, "evidence", None)
    if ev:
        ev = str(ev)
        # Evidence often bundles raw tool output with the curated confirmation proof
        # (appended as "[PROOF] ..."). Surface the proof prominently and cap the raw
        # dump — an unbounded evidence blob both reads unprofessionally and can exceed a
        # page, which throws a KeepTogether LayoutError.
        marker = ev.find("[PROOF]")
        proof_txt = ev[marker + len("[PROOF]"):].strip() if marker >= 0 else ""
        raw_txt = (ev[:marker] if marker >= 0 else ev).strip()

        omitted_style = ParagraphStyle("ev_more", parent=mono, textColor=_TEXT_MUTED)

        def _emit_capped(label, text, cap):
            lines = [l for l in text.split("\n") if l.strip()]  # drop blank noise
            if not lines:
                return
            inner.append(_p(label, lbl))
            for ln in lines[:cap]:
                inner.append(_p(_esc(ln), mono))
            if len(lines) > cap:
                inner.append(_p(f"… {len(lines) - cap} more line(s) omitted", omitted_style))

        # The curated proof is the client-relevant artefact — show it in full. The raw tool
        # dump (sqlmap banner art, request tracing) is kept to a short excerpt: it bloats the
        # card past a page (LayoutError, since the card is one non-splittable cell) and reads
        # as noise in a client report. Full raw output remains in the app + database.
        if proof_txt:
            _emit_capped("PROOF OF EXPLOITATION", proof_txt, 14)
            _emit_capped("TOOL OUTPUT (excerpt)", raw_txt, 4)
        else:
            _emit_capped("EVIDENCE", raw_txt, 14)

    # Compliance tag row
    comp = _normalize_compliance(_get(finding, "compliance"))
    if comp:
        inner.append(_p("COMPLIANCE MAPPING", lbl))
        tag_st = ParagraphStyle("comp_tag", fontSize=7.5,
                                fontName="Helvetica-Bold", textColor=_ACCENT,
                                alignment=TA_CENTER, leading=9)
        tag_cells = [_p(_esc(c), tag_st) for c in comp]
        tag_tbl = Table([tag_cells], colWidths=[_CARD_W / len(comp)] * len(comp))
        tag_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), _ACCENT_SOFT),
            ("BOX",           (0, 0), (-1, -1), 0.5, _ACCENT),
            ("INNERGRID",     (0, 0), (-1, -1), 0.5, colors.white),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ]))
        inner.append(Spacer(1, 2))
        inner.append(tag_tbl)

    # Wrap the whole card body in a bordered container with left padding
    card = Table([[inner]], colWidths=[_PAGE_W])
    card.setStyle(TableStyle([
        ("BOX",           (0, 0), (-1, -1), 0.75, _BORDER),
        ("LINEBEFORE",    (0, 0), (0, -1), 3, sev_color),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ("LEFTPADDING",   (0, 0), (-1, -1), 12),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 12),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]))

    return KeepTogether([card, Spacer(1, 0.18 * inch)])


# ── Fix-It Prompt (preserved, restyled) ──────────────────────────────────────

def _fix_prompt_page(fix_prompt: str, s) -> list:
    elems = _section_heading("Automated Remediation", "Fix-It Prompt", s)
    elems.append(_p(
        "Copy the prompt below and paste it into Cursor, Claude, or GitHub Copilot to "
        "automatically remediate the confirmed vulnerabilities found in this assessment.",
        s["muted"],
    ))
    elems.append(Spacer(1, 0.08 * inch))

    mono = ParagraphStyle(
        "prompt_line", fontName="Courier", fontSize=8, leading=11,
        leftIndent=12, rightIndent=12, textColor=colors.HexColor("#e2e8f0"),
    )
    lines = [
        _p(_esc(ln) if ln.strip() else "&nbsp;", mono)
        for ln in fix_prompt.split("\n")
    ]
    box = Table([[lines]], colWidths=[_PAGE_W])
    box.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), _BRAND_DARK),
        ("BOX",           (0, 0), (-1, -1), 0.75, _ACCENT),
        ("TOPPADDING",    (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
    ]))
    elems.append(box)
    return elems


# ── Page footer (every page except cover) ────────────────────────────────────

def _draw_footer(canvas, doc):
    canvas.saveState()
    page = canvas.getPageNumber()
    y = 0.5 * inch
    left = 0.75 * inch
    right = letter[0] - 0.75 * inch

    # thin rule
    canvas.setStrokeColor(_BORDER)
    canvas.setLineWidth(0.5)
    canvas.line(left, y + 12, right, y + 12)

    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(_TEXT_MUTED)
    canvas.drawString(left, y, "ArmorGuard — Confidential")
    canvas.drawRightString(right, y, f"Page {page}")
    canvas.restoreState()


def _draw_cover(canvas, doc):
    # Cover page intentionally has no footer.
    pass


# ── Entry point ──────────────────────────────────────────────────────────────

def generate_report_pdf(report, drift_event: dict | None = None) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=letter,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch,
        topMargin=0.75 * inch, bottomMargin=0.85 * inch,
        title="ArmorGuard Penetration Test Report",
        author="ArmorGuard",
    )
    base = getSampleStyleSheet()
    s = _styles(base)
    story = []

    generated = datetime.utcnow().strftime("%B %d, %Y  %H:%M UTC")

    # 1. Cover page (own page, no footer)
    story.extend(_cover_page(report, generated))

    # 2. Methodology & Scope
    story.extend(_methodology_page(report, generated, s))

    # 3. Executive Summary
    story.extend(_exec_summary(report, s))

    # 4. Intent-Drift Incident (preserved)
    if drift_event:
        story.extend(_section_heading("Governance Event", "Intent-Drift Incident", s))
        story.extend(_drift_section(drift_event, base))

    # 5. Findings
    findings = list(getattr(report, "findings", None) or [])
    if findings:
        story.append(PageBreak())
        story.extend(_section_heading("Detailed Results", "Confirmed Findings", s))
        try:
            ordered = sorted(
                findings,
                key=lambda f: _SEV_ORDER.index(getattr(f, "severity", "Low"))
                if getattr(f, "severity", "Low") in _SEV_ORDER else len(_SEV_ORDER),
            )
        except Exception:
            ordered = findings
        for i, f in enumerate(ordered, start=1):
            story.append(_finding_card(f, base, index=i))
    else:
        story.append(PageBreak())
        story.extend(_section_heading("Detailed Results", "Confirmed Findings", s))
        empty = ParagraphStyle("empty", parent=s["body"], textColor=_TEXT_MUTED)
        story.append(_p(
            "No confirmed findings were recorded for this assessment. All candidate "
            "weaknesses were either not present or could not be validated via proof-of-concept.",
            empty,
        ))

    # 6. Fix-It Prompt (preserved)
    if getattr(report, "fix_prompt", None):
        story.append(PageBreak())
        story.extend(_fix_prompt_page(report.fix_prompt, s))

    doc.build(story, onFirstPage=_draw_cover, onLaterPages=_draw_footer)
    return buffer.getvalue()
