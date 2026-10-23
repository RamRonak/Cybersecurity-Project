"""
PDF Security Report Generator for SecureScan.
Utilizes ReportLab to compile professional, publication-ready cybersecurity audit reports
with executive metrics, severity classification, evidence details, and remediation guidance.
"""

from io import BytesIO
import xml.sax.saxutils as saxutils
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


def safe_text(text: Any) -> str:
    """Escapes special characters to prevent XML parsing issues in ReportLab Paragraphs."""
    if text is None:
        return "None"
    s = str(text)
    # Truncate overly long single lines
    if len(s) > 1000:
        s = s[:1000] + " ... [truncated]"
    return saxutils.escape(s)


class NumberedCanvas(canvas.Canvas):
    """Custom canvas that tracks total pages to print 'Page X of Y' in footer."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))

        # Header (pages after first)
        if self._pageNumber > 1:
            self.drawString(
                54,
                750,
                "SecureScan — Automated Web Security Assessment Report",
            )
            self.setStrokeColor(colors.HexColor("#CBD5E1"))
            self.setLineWidth(0.5)
            self.line(54, 742, 558, 742)

        # Footer (all pages)
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)
        self.line(54, 45, 558, 45)

        footer_text = "CONFIDENTIAL & AUTHORIZED DEFENSIVE SECURITY EVALUATION"
        self.drawString(54, 32, footer_text)
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(558, 32, page_str)
        self.restoreState()


def generate_security_pdf(scan_data: dict[str, Any]) -> bytes:
    """
    Builds a complete, formatted PDF document in memory and returns raw bytes.

    Args:
        scan_data: The full scan result dictionary from scan_service.

    Returns:
        bytes: Binary PDF file content.
    """
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54,
    )

    styles = getSampleStyleSheet()

    # Custom typography styles
    brand_title = ParagraphStyle(
        "BrandTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=24,
        leading=28,
        textColor=colors.HexColor("#0F172A"),
    )
    report_subtitle = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#0284C7"),
    )
    section_heading = ParagraphStyle(
        "SectionHeading",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#0F172A"),
        spaceBefore=14,
        spaceAfter=6,
    )
    body_text = ParagraphStyle(
        "BodyTextCustom",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=14,
        textColor=colors.HexColor("#334155"),
    )
    meta_label = ParagraphStyle(
        "MetaLabel",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#475569"),
    )
    meta_val = ParagraphStyle(
        "MetaVal",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#0F172A"),
    )
    finding_title_style = ParagraphStyle(
        "FindingTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#0F172A"),
    )
    code_evidence = ParagraphStyle(
        "CodeEvidence",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#0F172A"),
    )

    story = []

    # 1. Header Banner & Title
    story.append(Paragraph("🛡️ SECURESCAN", brand_title))
    story.append(Paragraph("Automated Web Security Assessment & Configuration Audit", report_subtitle))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284C7"), spaceAfter=14))

    # 2. Executive Scan Metadata Table
    summary = scan_data.get("summary", {})
    metadata_table_data = [
        [
            Paragraph("<b>Target Hostname:</b>", meta_label),
            Paragraph(safe_text(scan_data.get("hostname", "N/A")), meta_val),
            Paragraph("<b>Scan Identifier:</b>", meta_label),
            Paragraph(safe_text(scan_data.get("scan_id", "N/A")), meta_val),
        ],
        [
            Paragraph("<b>Target URL:</b>", meta_label),
            Paragraph(safe_text(scan_data.get("target_url", "N/A")), meta_val),
            Paragraph("<b>Assessment Date:</b>", meta_label),
            Paragraph(safe_text(scan_data.get("timestamp", "N/A")), meta_val),
        ],
        [
            Paragraph("<b>Status:</b>", meta_label),
            Paragraph(safe_text(scan_data.get("status", "N/A")), meta_val),
            Paragraph("<b>Scan Duration:</b>", meta_label),
            Paragraph(f"{scan_data.get('duration_seconds', 0.0)} seconds", meta_val),
        ],
        [
            Paragraph("<b>Overall Posture Score:</b>", meta_label),
            Paragraph(f"<b>{summary.get('security_score', 'N/A')}/100 (Grade {summary.get('grade', 'N/A')})</b>", meta_val),
            Paragraph("<b>Assessment Type:</b>", meta_label),
            Paragraph("Passive Configuration Audit", meta_val),
        ],
    ]

    meta_table = Table(metadata_table_data, colWidths=[110, 150, 100, 144])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 14))

    # 3. Findings Severity Summary Cards Table
    story.append(Paragraph("Executive Severity Summary", section_heading))
    high_cnt = summary.get("high_count", 0)
    med_cnt = summary.get("medium_count", 0)
    low_cnt = summary.get("low_count", 0)
    info_cnt = summary.get("info_count", 0)

    summary_cards_data = [
        [
            Paragraph(f"<b>CRITICAL / HIGH</b><br/><font size='16'><b>{high_cnt}</b></font>", ParagraphStyle("H", parent=body_text, alignment=1, textColor=colors.HexColor("#EF4444"))),
            Paragraph(f"<b>MEDIUM</b><br/><font size='16'><b>{med_cnt}</b></font>", ParagraphStyle("M", parent=body_text, alignment=1, textColor=colors.HexColor("#F59E0B"))),
            Paragraph(f"<b>LOW</b><br/><font size='16'><b>{low_cnt}</b></font>", ParagraphStyle("L", parent=body_text, alignment=1, textColor=colors.HexColor("#0284C7"))),
            Paragraph(f"<b>INFORMATIONAL</b><br/><font size='16'><b>{info_cnt}</b></font>", ParagraphStyle("I", parent=body_text, alignment=1, textColor=colors.HexColor("#64748B"))),
        ]
    ]
    summary_cards_table = Table(summary_cards_data, colWidths=[126, 126, 126, 126])
    summary_cards_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#FEF2F2")),
        ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#FFFBEB")),
        ("BACKGROUND", (2, 0), (2, 0), colors.HexColor("#F0F9FF")),
        ("BACKGROUND", (3, 0), (3, 0), colors.HexColor("#F8FAFC")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(summary_cards_table)
    story.append(Spacer(1, 14))

    # 4. Scope, Methodology & Authorization
    story.append(Paragraph("Scope & Defensive Methodology", section_heading))
    methodology_text = (
        "This security assessment was executed strictly under authorized defensive conditions using non-destructive, "
        "passive HTTP/HTTPS configuration analysis. Checks evaluate transport security enforcement (TLS/HTTPS), "
        "HTTP security response headers (CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, "
        "Permissions-Policy), Cross-Origin Resource Sharing (CORS) boundaries, and cookie security flags (Secure, "
        "HttpOnly, SameSite). No destructive exploits, payload injection, or brute-force tests were performed."
    )
    story.append(Paragraph(methodology_text, body_text))
    story.append(Spacer(1, 14))

    # 5. Detailed Findings Section
    story.append(Paragraph("Detailed Security Findings", section_heading))
    findings = scan_data.get("findings", [])

    if not findings:
        story.append(Paragraph(
            "<b>No security weaknesses detected by the passive configuration checks.</b><br/>"
            "<i>Note: A clean passive scan does not guarantee that the application is immune to business logic, "
            "authentication, or server-side injection vulnerabilities. Comprehensive penetration testing is recommended.</i>",
            body_text,
        ))
    else:
        for idx, finding in enumerate(findings, start=1):
            sev = finding.get("severity", "Informational")
            sev_colors = {
                "High": ("#EF4444", "#FEF2F2"),
                "Medium": ("#F59E0B", "#FFFBEB"),
                "Low": ("#0284C7", "#F0F9FF"),
                "Informational": ("#64748B", "#F8FAFC"),
            }
            border_col, bg_col = sev_colors.get(sev, ("#64748B", "#F8FAFC"))

            finding_flowables = [
                Spacer(1, 6),
                Paragraph(
                    f"<b>Finding {idx} [{safe_text(finding.get('id'))}] — {safe_text(finding.get('title'))}</b>",
                    finding_title_style,
                ),
                Spacer(1, 4),
            ]

            table_content = [
                [Paragraph("<b>Severity:</b>", meta_label), Paragraph(f"<b>{safe_text(sev)}</b>", meta_val),
                 Paragraph("<b>Category:</b>", meta_label), Paragraph(safe_text(finding.get("category")), meta_val)],
                [Paragraph("<b>Affected:</b>", meta_label), Paragraph(safe_text(finding.get("affected_component")), meta_val),
                 Paragraph("<b>Confidence:</b>", meta_label), Paragraph(safe_text(finding.get("confidence", "High")), meta_val)],
                [Paragraph("<b>Evidence:</b>", meta_label), Paragraph(safe_text(finding.get("evidence")), code_evidence), "", ""],
                [Paragraph("<b>Explanation:</b>", meta_label), Paragraph(safe_text(finding.get("explanation")), body_text), "", ""],
                [Paragraph("<b>Impact:</b>", meta_label), Paragraph(safe_text(finding.get("impact")), body_text), "", ""],
                [Paragraph("<b>Remediation:</b>", meta_label), Paragraph(safe_text(finding.get("remediation")), body_text), "", ""],
            ]

            f_table = Table(table_content, colWidths=[90, 414])
            f_table.setStyle(TableStyle([
                ("SPAN", (1, 2), (-1, 2)),
                ("SPAN", (1, 3), (-1, 3)),
                ("SPAN", (1, 4), (-1, 4)),
                ("SPAN", (1, 5), (-1, 5)),
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(bg_col)),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor(border_col)),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]))

            finding_flowables.append(f_table)
            finding_flowables.append(Spacer(1, 10))
            story.append(KeepTogether(finding_flowables))

    # 6. Limitations & Disclaimer Section
    story.append(Spacer(1, 10))
    story.append(Paragraph("Limitations & Legal Disclaimer", section_heading))
    disclaimer_text = (
        "SecureScan is an educational and defensive audit tool designed to evaluate HTTP header hygiene and network transport "
        "configuration. It does not exploit weaknesses, inject SQL, execute XSS vectors, or perform state-changing "
        "vulnerability assessments. The absence of findings does not certify an application as invulnerable. Testing must "
        "always be authorized by the application owner. The evaluators and authors assume no liability for misuse."
    )
    story.append(Paragraph(disclaimer_text, ParagraphStyle("Disc", parent=body_text, fontName="Helvetica-Oblique", textColor=colors.HexColor("#64748B"))))

    # Build document with custom canvas for page numbering
    doc.build(story, canvasmaker=NumberedCanvas)
    buffer.seek(0)
    return buffer.getvalue()
