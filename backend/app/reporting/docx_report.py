"""Word (.docx) report export (§8) via python-docx — pure Python, no
native dependency. Same content as the HTML/PDF reports: executive
summary, severity summary table, and one section per finding.
"""

import io
import uuid

from docx import Document
from docx.shared import Inches, Pt, RGBColor

from app.models.finding import Finding
from app.schemas.scan import ScanRunDetail

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
SEVERITY_RGB = {
    "Critical": RGBColor(0x7F, 0x1D, 0x1D),
    "High": RGBColor(0xB9, 0x1C, 0x1C),
    "Medium": RGBColor(0xB4, 0x53, 0x09),
    "Low": RGBColor(0x25, 0x63, 0xEB),
}

_MAX_EVIDENCE_CHARS = 3000


def _mono_paragraph(document: Document, text: str) -> None:
    paragraph = document.add_paragraph()
    run = paragraph.add_run((text or "")[:_MAX_EVIDENCE_CHARS])
    run.font.name = "Courier New"
    run.font.size = Pt(8)


def render_docx_report(
    *,
    scan_run: ScanRunDetail,
    findings: list[Finding],
    executive_summary: str,
    screenshots_by_finding_id: dict[uuid.UUID, list[bytes]] | None = None,
) -> bytes:
    screenshots_by_finding_id = screenshots_by_finding_id or {}
    ordered = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    document = Document()

    document.add_heading("Verdikt Security Assessment Report", level=1)
    document.add_paragraph(f"Scan run {scan_run.id} — status: {scan_run.status}")

    document.add_heading("Executive Summary", level=2)
    document.add_paragraph(executive_summary)

    document.add_heading("Summary", level=2)
    table = document.add_table(rows=1, cols=2)
    table.style = "Light Grid Accent 1"
    header_cells = table.rows[0].cells
    header_cells[0].text = "Severity"
    header_cells[1].text = "Count"
    for sev in ("Critical", "High", "Medium", "Low"):
        row = table.add_row().cells
        row[0].text = sev
        row[1].text = str(scan_run.finding_counts_by_severity.get(sev, 0))

    document.add_heading("Findings", level=2)
    if not ordered:
        document.add_paragraph("No confirmed findings for this scan run.")

    for finding in ordered:
        document.add_page_break()
        heading = document.add_heading(level=2)
        run = heading.add_run(f"[{finding.severity}] {finding.title}")
        run.font.color.rgb = SEVERITY_RGB.get(finding.severity, RGBColor(0, 0, 0))

        meta = document.add_paragraph()
        meta.add_run(
            f"{finding.owasp_2025_category} | {finding.cwe_id} | "
            f"CVSS {finding.cvss_score} ({finding.cvss_vector})"
        ).italic = True

        document.add_heading("What this means", level=3)
        document.add_paragraph(finding.plain_language_summary)

        document.add_heading("Technical detail", level=3)
        document.add_paragraph(finding.technical_description)

        if finding.affected_endpoints:
            document.add_heading("Affected endpoint(s)", level=3)
            for endpoint in finding.affected_endpoints:
                document.add_paragraph(endpoint, style="List Bullet")

        if finding.steps_to_reproduce:
            document.add_heading("Steps to reproduce", level=3)
            for step in finding.steps_to_reproduce:
                document.add_paragraph(step, style="List Number")

        document.add_heading("Remediation", level=3)
        document.add_paragraph(finding.remediation)

        if finding.evidence:
            document.add_heading("Evidence — request", level=3)
            _mono_paragraph(document, finding.evidence.request_raw)
            document.add_heading("Evidence — response", level=3)
            _mono_paragraph(document, finding.evidence.response_raw)

        for image_bytes in screenshots_by_finding_id.get(finding.id, []):
            document.add_heading("Evidence — screenshot", level=3)
            try:
                document.add_picture(io.BytesIO(image_bytes), width=Inches(5))
            except Exception:  # noqa: BLE001 — a corrupt/unreadable image must not break report generation
                document.add_paragraph("(screenshot could not be embedded)")

    buffer = io.BytesIO()
    document.save(buffer)
    return buffer.getvalue()
