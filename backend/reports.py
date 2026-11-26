"""
ForensiTrace Forensic PDF Report Generator
Author: Purva (Backend, Data Layer & Reporting Owner)
Contract: docs/ml.md Section 7.2 & Step 4 of Execution Plan

Generates a standardized 3-page Forensic Investigation Report with Raw Evidence Appendix:
- Page 1: Case Summary, Threat Level Badge, Dual-Tier Scores (Rule + ML), and Narrative
- Page 2: Reconstructed Chronological Timeline & Provenance Evidence Table
- Page 3: Appendix of Unedited Raw Telemetry Payloads (for independent verification)
"""

from __future__ import annotations

import io
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

logger = logging.getLogger("forensitrace.reports")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(levelname)s] [%(name)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


THREAT_COLORS: Dict[str, colors.Color] = {
    "CRITICAL": colors.HexColor("#B91C1C"),  # Deep Red
    "HIGH": colors.HexColor("#D97706"),      # Dark Amber/Orange
    "MEDIUM": colors.HexColor("#CA8A04"),    # Amber Yellow
    "LOW": colors.HexColor("#15803D"),       # Forest Green
}

PRIMARY_DARK = colors.HexColor("#0F172A")    # Slate 900
PRIMARY_ACCENT = colors.HexColor("#1E3A8A")  # Deep Blue
LIGHT_BG = colors.HexColor("#F8FAFC")        # Slate 50
BORDER_COLOR = colors.HexColor("#CBD5E1")    # Slate 300
CODE_BG = colors.HexColor("#F1F5F9")         # Slate 100


def _safe(val: Any) -> str:
    """Safely converts any value to XML-escaped string for ReportLab Paragraphs."""
    if val is None:
        return "N/A"
    return escape(str(val))


def _wrap_long_text(text: str, max_line_len: int = 88) -> List[str]:
    """Splits long lines for safe rendering in Page 3 raw log blocks without overflow."""
    lines: List[str] = []
    for raw_line in text.splitlines():
        if len(raw_line) <= max_line_len:
            lines.append(raw_line)
        else:
            for i in range(0, len(raw_line), max_line_len):
                lines.append(raw_line[i : i + max_line_len])
    return lines or [""]


def _add_page_footer(canvas: Any, doc: Any) -> None:
    """Draws consistent header/footer metadata on every PDF page."""
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#64748B"))
    footer_left = "ForensiTrace — Forensic Investigation Report (Confidential)"
    footer_right = f"Page {doc.page}"
    canvas.drawString(0.65 * inch, 0.45 * inch, footer_left)
    canvas.drawRightString(letter[0] - 0.65 * inch, 0.45 * inch, footer_right)
    canvas.restoreState()


def generate_activity_pdf_bytes(activity: Dict[str, Any]) -> bytes:
    """
    Generates the 3-page Forensic Investigation Report PDF as raw bytes.
    Expects an activity dictionary matching backend.db.get_activity_by_id(..., include_evidence=True).
    """
    activity_id = activity.get("activity_id", "UNKNOWN")
    evidence_chain: List[Dict[str, Any]] = activity.get("evidence_chain") or []
    logger.info(
        "[generate_activity_pdf_bytes] [RECEIVED] activity_id='%s' with %d evidence event(s)",
        activity_id,
        len(evidence_chain),
    )

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=0.65 * inch,
        rightMargin=0.65 * inch,
        topMargin=0.65 * inch,
        bottomMargin=0.70 * inch,
        title=f"ForensiTrace Forensic Report - {activity_id}",
        author="ForensiTrace Automated Correlation & Reporting Engine",
    )

    base_styles = getSampleStyleSheet()
    styles = {
        "title": ParagraphStyle(
            "FTTitle",
            parent=base_styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=16,
            leading=20,
            textColor=colors.white,
        ),
        "subtitle": ParagraphStyle(
            "FTSubtitle",
            parent=base_styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#E2E8F0"),
        ),
        "section": ParagraphStyle(
            "FTSection",
            parent=base_styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=16,
            textColor=PRIMARY_DARK,
            spaceBefore=10,
            spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "FTBody",
            parent=base_styles["Normal"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=13.5,
            textColor=colors.HexColor("#1E293B"),
        ),
        "small": ParagraphStyle(
            "FTSmall",
            parent=base_styles["Normal"],
            fontName="Helvetica",
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#475569"),
        ),
        "cell": ParagraphStyle(
            "FTCell",
            parent=base_styles["Normal"],
            fontName="Helvetica",
            fontSize=8,
            leading=10.5,
            textColor=colors.HexColor("#0F172A"),
            wordWrap="CJK",
        ),
        "cell_bold": ParagraphStyle(
            "FTCellBold",
            parent=base_styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10.5,
            textColor=colors.HexColor("#0F172A"),
        ),
        "code": ParagraphStyle(
            "FTCode",
            parent=base_styles["Normal"],
            fontName="Courier",
            fontSize=7.2,
            leading=9.2,
            textColor=colors.HexColor("#0F172A"),
        ),
    }

    story: List[Any] = []
    usable_width = letter[0] - 1.3 * inch

    # Extract derived metadata
    threat_level = str(activity.get("threat_level") or "MEDIUM").upper()
    threat_color = THREAT_COLORS.get(threat_level, THREAT_COLORS["MEDIUM"])
    rule_conf = float(activity.get("confidence", 0.0))
    ml_score_raw = activity.get("ml_anomaly_score")
    ml_score_str = f"{float(ml_score_raw):.2f}" if ml_score_raw is not None else "N/A (Offline)"
    if ml_score_raw is not None:
        combined_index = 0.5 * rule_conf + 0.5 * float(ml_score_raw)
        combined_str = f"{combined_index:.2f}"
    else:
        combined_str = f"{rule_conf:.2f} (Rule-Only Fallback)"

    hosts = sorted({str(e.get("host")) for e in evidence_chain if e.get("host")})
    users = sorted({str(e.get("user")) for e in evidence_chain if e.get("user")})
    host_display = ", ".join(hosts) if hosts else "Unattributed"
    user_display = ", ".join(users) if users else "Unattributed / SYSTEM"
    generated_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # =========================================================================
    # PAGE 1: CASE SUMMARY, THREAT BADGE, HYBRID SCORING & NARRATIVE
    # =========================================================================
    banner_data = [
        [
            Paragraph("FORENSITRACE — FORENSIC INVESTIGATION REPORT", styles["title"]),
            Paragraph(f"<b>THREAT: {_safe(threat_level)}</b>", ParagraphStyle(
                "BadgeText",
                parent=base_styles["Normal"],
                fontName="Helvetica-Bold",
                fontSize=10,
                alignment=1,
                textColor=colors.white,
            )),
        ],
        [
            Paragraph(
                f"Activity Case ID: {_safe(activity_id)} &nbsp;|&nbsp; Generated: {_safe(generated_utc)}",
                styles["subtitle"],
            ),
            "",
        ],
    ]
    banner_table = Table(banner_data, colWidths=[usable_width * 0.76, usable_width * 0.24])
    banner_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 1), PRIMARY_DARK),
        ("BACKGROUND", (1, 0), (1, 1), threat_color),
        ("SPAN", (1, 0), (1, 1)),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(banner_table)
    story.append(Spacer(1, 0.20 * inch))

    # Case Metadata Table
    story.append(Paragraph("1. Case Summary & Target Attribution", styles["section"]))
    meta_rows = [
        [Paragraph("<b>Activity ID</b>", styles["cell_bold"]), Paragraph(_safe(activity_id), styles["cell"]),
         Paragraph("<b>Correlation Rule</b>", styles["cell_bold"]), Paragraph(f"{_safe(activity.get('rule_id'))} — {_safe(activity.get('rule_name'))}", styles["cell"])],
        [Paragraph("<b>Target Host(s)</b>", styles["cell_bold"]), Paragraph(_safe(host_display), styles["cell"]),
         Paragraph("<b>Observed User(s)</b>", styles["cell_bold"]), Paragraph(_safe(user_display), styles["cell"])],
        [Paragraph("<b>Window Start (UTC)</b>", styles["cell_bold"]), Paragraph(_safe(activity.get("ts_start_utc")), styles["cell"]),
         Paragraph("<b>Window End (UTC)</b>", styles["cell_bold"]), Paragraph(_safe(activity.get("ts_end_utc")), styles["cell"])],
        [Paragraph("<b>Supporting Events</b>", styles["cell_bold"]), Paragraph(str(len(evidence_chain)), styles["cell"]),
         Paragraph("<b>Threat Classification</b>", styles["cell_bold"]), Paragraph(f"<b>{_safe(threat_level)}</b>", styles["cell"])],
    ]
    meta_table = Table(meta_rows, colWidths=[usable_width * 0.20, usable_width * 0.30, usable_width * 0.20, usable_width * 0.30])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), LIGHT_BG),
        ("BACKGROUND", (2, 0), (2, -1), LIGHT_BG),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.18 * inch))

    # Hybrid Dual-Tier Evaluation Metrics
    story.append(Paragraph("2. Hybrid Assessment Scores (Tier 1 ML + Tier 2 Rules)", styles["section"]))
    score_rows = [
        [
            Paragraph("<b>Tier 2: Rule Confidence</b><br/><font size='7' color='#64748B'>Deterministic Evidence Completeness</font>", styles["cell_bold"]),
            Paragraph("<b>Tier 1: ML Anomaly Score</b><br/><font size='7' color='#64748B'>Normalized LSTM Reconstruction Error</font>", styles["cell_bold"]),
            Paragraph("<b>Combined Risk Index</b><br/><font size='7' color='#64748B'>0.5 Rule + 0.5 ML Heuristic</font>", styles["cell_bold"]),
        ],
        [
            Paragraph(f"<font size='13'><b>{rule_conf:.2f}</b></font> <font size='8'>/ 1.00</font>", styles["cell"]),
            Paragraph(f"<font size='13'><b>{_safe(ml_score_str)}</b></font> <font size='8'>/ 1.00</font>", styles["cell"]),
            Paragraph(f"<font size='13'><b>{_safe(combined_str)}</b></font>", styles["cell"]),
        ],
    ]
    score_table = Table(score_rows, colWidths=[usable_width / 3.0] * 3)
    score_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), LIGHT_BG),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(score_table)
    story.append(Spacer(1, 0.18 * inch))

    # Plain-English Forensic Narrative
    story.append(Paragraph("3. Incident Narrative & Analytical Summary", styles["section"]))
    narrative_text = activity.get("narrative") or "No narrative explanation recorded for this activity."
    narrative_box = Table(
        [[Paragraph(_safe(narrative_text), styles["body"])]],
        colWidths=[usable_width],
    )
    narrative_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), LIGHT_BG),
        ("BOX", (0, 0), (-1, -1), 0.75, PRIMARY_ACCENT),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(narrative_box)
    story.append(Spacer(1, 0.22 * inch))

    # Methodology & Forensic Scope Note
    story.append(Paragraph("4. Evidentiary Methodology Note", styles["section"]))
    methodology_note = (
        "This forensic investigation report documents correlated Windows endpoint telemetry across USB device "
        "management, file system activity, and Windows Security/System Event Logs. Tier 2 correlation rules provide "
        "deterministic causal links grounded directly in raw event records. Where available, Tier 1 provides an LSTM "
        "autoencoder anomaly score (normalized reconstruction error between 0.00 and 1.00 relative to normal workstation "
        "baselines). The ML anomaly score supplements analytical triage and never replaces raw evidentiary provenance."
    )
    story.append(Paragraph(methodology_note, styles["small"]))

    # =========================================================================
    # PAGE 2: RECONSTRUCTED TIMELINE & EVIDENCE TABLE
    # =========================================================================
    story.append(PageBreak())
    story.append(Paragraph("5. Reconstructed Evidence Timeline & Provenance Chain", styles["section"]))
    story.append(Paragraph(
        f"Chronological sequence of {len(evidence_chain)} supporting telemetry record(s) linked to activity <b>{_safe(activity_id)}</b>.",
        styles["small"],
    ))
    story.append(Spacer(1, 0.12 * inch))

    if evidence_chain:
        ev_rows = [[
            Paragraph("<b>#</b>", styles["cell_bold"]),
            Paragraph("<b>Timestamp (UTC)</b>", styles["cell_bold"]),
            Paragraph("<b>Source</b>", styles["cell_bold"]),
            Paragraph("<b>Action</b>", styles["cell_bold"]),
            Paragraph("<b>Target Entity</b>", styles["cell_bold"]),
            Paragraph("<b>Provenance Justification</b>", styles["cell_bold"]),
        ]]

        for idx, ev in enumerate(evidence_chain, start=1):
            ev_rows.append([
                Paragraph(str(idx), styles["cell"]),
                Paragraph(_safe(ev.get("ts_utc")), styles["cell"]),
                Paragraph(_safe(ev.get("source")).upper(), styles["cell"]),
                Paragraph(_safe(ev.get("action")), styles["cell"]),
                Paragraph(_safe(ev.get("entity")), styles["cell"]),
                Paragraph(_safe(ev.get("reason")), styles["cell"]),
            ])

        col_widths = [
            usable_width * 0.05,
            usable_width * 0.19,
            usable_width * 0.10,
            usable_width * 0.16,
            usable_width * 0.25,
            usable_width * 0.25,
        ]
        ev_table = Table(ev_rows, colWidths=col_widths, repeatRows=1)
        ev_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), PRIMARY_DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_BG]),
            ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]))
        # Override header paragraph text color cleanly via custom ParagraphStyle
        ev_rows[0] = [
            Paragraph(f"<font color='white'><b>{h}</b></font>", styles["cell_bold"])
            for h in ["#", "Timestamp (UTC)", "Source", "Action", "Target Entity", "Provenance Justification"]
        ]
        ev_table = Table(ev_rows, colWidths=col_widths, repeatRows=1)
        ev_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), PRIMARY_DARK),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_BG]),
            ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(ev_table)
    else:
        story.append(Paragraph("<i>No individual supporting event links recorded for this activity.</i>", styles["body"]))

    # =========================================================================
    # PAGE 3: UNEDITED RAW EVENT APPENDIX
    # =========================================================================
    story.append(PageBreak())
    story.append(Paragraph("6. Appendix: Unedited Raw Telemetry Records", styles["section"]))
    story.append(Paragraph(
        "The verbatim raw source records below are preserved directly from endpoint telemetry collectors for independent verification.",
        styles["small"],
    ))
    story.append(Spacer(1, 0.12 * inch))

    if evidence_chain:
        for idx, ev in enumerate(evidence_chain, start=1):
            ev_id = ev.get("event_id", "unknown")
            src = str(ev.get("source", "")).upper()
            ts = ev.get("ts_utc", "N/A")
            header_html = f"<b>Event #{idx}</b> &nbsp;|&nbsp; <b>ID:</b> {_safe(ev_id)} &nbsp;|&nbsp; <b>Source:</b> {_safe(src)} &nbsp;|&nbsp; <b>UTC:</b> {_safe(ts)}"
            story.append(Paragraph(header_html, styles["cell_bold"]))
            story.append(Spacer(1, 0.04 * inch))

            raw_payload = ev.get("raw")
            try:
                raw_pretty = json.dumps(raw_payload, indent=2, ensure_ascii=False)
            except Exception:
                raw_pretty = str(raw_payload)

            wrapped_lines = _wrap_long_text(raw_pretty, max_line_len=92)
            # Chunk lines cleanly so massive raw records never trigger ReportLab LayoutError
            chunk_size = 24
            for c_start in range(0, len(wrapped_lines), chunk_size):
                chunk_text = "\n".join(wrapped_lines[c_start : c_start + chunk_size])
                escaped_code = escape(chunk_text).replace(" ", "&nbsp;").replace("\n", "<br/>")
                code_box = Table([[Paragraph(escaped_code, styles["code"])]], colWidths=[usable_width])
                code_box.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), CODE_BG),
                    ("BOX", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]))
                story.append(code_box)
                story.append(Spacer(1, 0.04 * inch))

            story.append(Spacer(1, 0.10 * inch))
    else:
        story.append(Paragraph("<i>No raw event telemetry records attached.</i>", styles["body"]))

    doc.build(story, onFirstPage=_add_page_footer, onLaterPages=_add_page_footer)
    pdf_bytes = buffer.getvalue()
    buffer.close()

    logger.info(
        "[generate_activity_pdf_bytes] [PRODUCED] Generated %d-byte PDF report for activity_id='%s'",
        len(pdf_bytes),
        activity_id,
    )
    return pdf_bytes
