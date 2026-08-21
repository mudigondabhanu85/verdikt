"""PDF report export (§8) via reportlab — pure Python, no native
dependency (WeasyPrint's Pango/Cairo requirement wasn't satisfiable in
the build sandbox, see the Phase 5 planning notes). Same content as the
HTML report (app.reporting.html_report): executive summary, severity
summary table, and one section per finding with plain-language +
technical descriptions, reproduction steps, remediation, and evidence.
"""

import io

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    ListFlowable,
    ListItem,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.models.finding import Finding
from app.schemas.scan import ScanRunDetail

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
SEVERITY_HEX = {
    "Critical": "#7f1d1d",
    "High": "#b91c1c",
    "Medium": "#b45309",
    "Low": "#2563eb",
}

_styles = getSampleStyleSheet()
_body = _styles["BodyText"]
_h1 = _styles["Heading1"]
_h2 = _styles["Heading2"]
_h3 = _styles["Heading3"]
_mono = ParagraphStyle("Mono", parent=_body, fontName="Courier", fontSize=8, leading=10)

_MAX_EVIDENCE_CHARS = 3000


def _escape(text: str | None) -> str:
    return (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _escape_pre(text: str | None) -> str:
    truncated = (text or "")[:_MAX_EVIDENCE_CHARS]
    return _escape(truncated).replace("\n", "<br/>")


def render_pdf_report(
    *, scan_run: ScanRunDetail, findings: list[Finding], executive_summary: str
) -> bytes:
    ordered = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=LETTER, title="Verdikt Security Assessment Report")
    story: list = []

    story.append(Paragraph("Verdikt Security Assessment Report", _h1))
    story.append(Paragraph(f"Scan run {scan_run.id} — status: {scan_run.status}", _body))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Executive Summary", _h2))
    story.append(Paragraph(_escape(executive_summary), _body))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Summary", _h2))
    table_data = [["Severity", "Count"]] + [
        [sev, str(scan_run.finding_counts_by_severity.get(sev, 0))]
        for sev in ("Critical", "High", "Medium", "Low")
    ]
    table = Table(table_data, colWidths=[2 * inch, 1 * inch])
    table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f0f0f0")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ]
        )
    )
    story.append(table)
    story.append(Spacer(1, 12))

    story.append(Paragraph("Findings", _h2))
    if not ordered:
        story.append(Paragraph("No confirmed findings for this scan run.", _body))

    for finding in ordered:
        story.append(PageBreak())
        color_hex = SEVERITY_HEX.get(finding.severity, "#000000")
        story.append(
            Paragraph(
                f'<font color="{color_hex}">[{finding.severity}]</font> {_escape(finding.title)}', _h2
            )
        )
        story.append(
            Paragraph(
                f"{_escape(finding.owasp_2025_category)} | {_escape(finding.cwe_id)} | "
                f"CVSS {finding.cvss_score} ({_escape(finding.cvss_vector)})",
                _body,
            )
        )
        story.append(Spacer(1, 6))

        story.append(Paragraph("What this means", _h3))
        story.append(Paragraph(_escape(finding.plain_language_summary), _body))

        story.append(Paragraph("Technical detail", _h3))
        story.append(Paragraph(_escape(finding.technical_description), _body))

        if finding.affected_endpoints:
            story.append(Paragraph("Affected endpoint(s)", _h3))
            story.append(
                ListFlowable(
                    [ListItem(Paragraph(_escape(e), _mono)) for e in finding.affected_endpoints],
                    bulletType="bullet",
                )
            )

        if finding.steps_to_reproduce:
            story.append(Paragraph("Steps to reproduce", _h3))
            story.append(
                ListFlowable(
                    [ListItem(Paragraph(_escape(s), _body)) for s in finding.steps_to_reproduce],
                    bulletType="1",
                )
            )

        story.append(Paragraph("Remediation", _h3))
        story.append(Paragraph(_escape(finding.remediation), _body))

        if finding.evidence:
            story.append(Paragraph("Evidence — request", _h3))
            story.append(Paragraph(_escape_pre(finding.evidence.request_raw), _mono))
            story.append(Paragraph("Evidence — response", _h3))
            story.append(Paragraph(_escape_pre(finding.evidence.response_raw), _mono))

    doc.build(story)
    return buffer.getvalue()
