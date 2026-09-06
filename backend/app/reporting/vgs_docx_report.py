"""Ported, real logic from the user's standalone VGS tool's own
webapp/routers/report.py (read in full at merge time) — the pie chart
color mapping, the version-history table rows, and the numbered
summary-table-with-page-references are all real details carried over
from that file, not reinvented. Adapted to pull from Verdikt's own
VgsReportDraft/VgsReportVulnerability/VgsEvidenceStep models and object
storage instead of VGS's original request-payload/local-disk shape, and
to use Verdikt's real org branding instead of VGS's separate logo
library (see app.models.org_branding.OrgBranding).
"""

import io
import uuid
from collections import Counter
from datetime import datetime

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from matplotlib.patches import Patch

from app.models.vgs_vulnerability import VgsEvidenceStep, VgsReportDraft, VgsReportVulnerability
from app.reporting.html_report import BrandingInfo

_SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]
_SEVERITY_COLORS = {
    "Critical": RGBColor(128, 0, 0),
    "High": RGBColor(255, 0, 0),
    "Medium": RGBColor(255, 191, 0),
    "Low": RGBColor(0, 128, 0),
}
# Real color mapping from VGS's own generate_pie_chart() — matplotlib
# color names, not the RGBColor values used for docx text above.
_PIE_COLOR_MAP = {
    "Critical": "maroon",
    "High": "red",
    "Medium": "orange",
    "Low": "green",
}


def _generate_pie_chart(vulnerabilities: list[VgsReportVulnerability]) -> bytes:
    """Real port of VGS's generate_pie_chart(): a severity-distribution
    pie with raw counts (not percentages) shown via a custom autopct,
    and a legend listing "{count} {severity}" per slice."""
    severity_counts = Counter(v.severity for v in vulnerabilities)
    labels = [sev for sev in _SEVERITY_ORDER if severity_counts[sev] > 0]
    sizes = [severity_counts[sev] for sev in labels]
    colors = [_PIE_COLOR_MAP[sev] for sev in labels]

    def _make_autopct(values):
        def _autopct(pct):
            total = sum(values)
            val = int(round(pct * total / 100.0))
            return f"{val}" if val > 0 else ""

        return _autopct

    fig = plt.figure(figsize=(4, 4))
    _wedges, _texts, autotexts = plt.pie(
        sizes, labels=labels, colors=colors, autopct=_make_autopct(sizes), startangle=140
    )
    for autotext in autotexts:
        autotext.set_color("white")
        autotext.set_fontsize(10)
        autotext.set_weight("bold")

    legend_labels = [f"{severity_counts[sev]} {sev}" for sev in labels]
    patches = [Patch(color=_PIE_COLOR_MAP[sev], label=legend_labels[i]) for i, sev in enumerate(labels)]
    plt.legend(handles=patches, loc="best")
    plt.axis("equal")
    plt.tight_layout()

    buf = io.BytesIO()
    fig.savefig(buf, format="png")
    plt.close(fig)
    return buf.getvalue()


def render_vgs_docx_report(
    *,
    draft: VgsReportDraft,
    vulnerabilities: list[VgsReportVulnerability],
    evidence_steps_by_vuln_id: dict[uuid.UUID, list[VgsEvidenceStep]],
    screenshot_bytes_by_object_key: dict[str, bytes],
    branding: BrandingInfo | None = None,
) -> bytes:
    document = Document()
    document.styles["Normal"].font.name = "Calibri"
    document.styles["Normal"].font.size = Pt(11)

    # Cover-page logo, real port of VGS's dynamic-logo-path handling.
    if branding and branding.logo_bytes:
        para = document.add_paragraph()
        para.alignment = 1
        try:
            para.add_run().add_picture(io.BytesIO(branding.logo_bytes), width=Inches(2.5))
        except Exception:  # noqa: BLE001 — a corrupt/unreadable logo must not break report generation
            pass

    title = document.add_paragraph("\n\nDynamic Vulnerability Assessment")
    title.alignment = 1
    run = title.runs[0]
    run.bold = True
    run.font.size = Pt(28)
    run.font.color.rgb = RGBColor(0, 102, 204)

    app_title = document.add_paragraph(draft.app_title)
    app_title.alignment = 1
    if app_title.runs:
        run = app_title.runs[0]
        run.bold = True
        run.font.size = Pt(26)
        run.font.color.rgb = RGBColor(0, 102, 204)

    requester = document.add_paragraph()
    req_run = requester.add_run("Requested by: ")
    req_run.bold = True
    requester.add_run(draft.requester_name)

    document.add_page_break()

    # Real port of VGS's header-logo-on-every-page + confidentiality footer.
    section = document.sections[0]
    if branding and branding.logo_bytes:
        header_para = section.header.paragraphs[0]
        header_para.alignment = 2
        try:
            header_para.add_run().add_picture(io.BytesIO(branding.logo_bytes), width=Inches(1.0))
        except Exception:  # noqa: BLE001
            pass
    footer = section.footer.paragraphs[0]
    footer.text = "Confidential - For Internal Use Only"
    footer.alignment = 1

    # Real port of VGS's Version Information / review-history table.
    document.add_heading("Version Information", level=2)
    table = document.add_table(rows=4, cols=3)
    table.style = "Table Grid"
    for i, header in enumerate(["Date", "Application Version", "Reviewer"]):
        table.cell(0, i).text = header
    today = datetime.now().strftime("%d-%b-%Y")
    table.cell(1, 0).text = today
    table.cell(1, 1).text = "Initial Draft"
    table.cell(1, 2).text = draft.analyst_name
    table.cell(2, 0).text = today
    table.cell(2, 1).text = "Peer Review"
    table.cell(3, 0).text = today
    table.cell(3, 1).text = "Approved"

    document.add_page_break()

    if vulnerabilities:
        pie_bytes = _generate_pie_chart(vulnerabilities)
        document.add_paragraph().add_run("Vulnerability Severity Distribution").bold = True
        document.add_picture(io.BytesIO(pie_bytes), width=Inches(4.5))
        document.paragraphs[-1].alignment = 1
        document.add_page_break()

    # Real port of VGS's grouped-by-severity numbered Summary Table with
    # page-number references.
    document.add_heading("Summary Table", level=2)
    summary_table = document.add_table(rows=1, cols=4)
    summary_table.style = "Table Grid"
    for i, header in enumerate(["Sl. No.", "Security Observation", "Risk Rating", "Page No."]):
        summary_table.cell(0, i).text = header

    count = 1
    page_counter = 4
    for sev in _SEVERITY_ORDER:
        group = [v for v in vulnerabilities if v.severity == sev]
        if not group:
            continue
        row = summary_table.add_row().cells
        row[0].merge(row[3])
        heading = row[0].paragraphs[0].add_run(f"{sev} Severity")
        heading.bold = True
        heading.font.color.rgb = _SEVERITY_COLORS[sev]
        for vuln in group:
            row = summary_table.add_row().cells
            row[0].text = str(count)
            row[1].text = vuln.title
            risk = row[2].paragraphs[0].add_run(vuln.severity)
            risk.font.color.rgb = _SEVERITY_COLORS.get(vuln.severity, RGBColor(0, 0, 0))
            row[3].text = str(page_counter)
            count += 1
            page_counter += 1

    document.add_page_break()
    document.add_heading("URLs and Scope", level=2)
    document.add_paragraph(f"URLs: {draft.urls}")
    document.add_paragraph(f"Scope: {draft.scope}")
    document.add_page_break()

    document.add_heading("Vulnerability Details", level=2)
    for idx, vuln in enumerate(vulnerabilities, 1):
        document.add_page_break()
        document.add_heading(f"{idx}. {vuln.title}", level=3)

        para = document.add_paragraph()
        para.add_run("Severity: ").bold = True
        sev_run = para.add_run(vuln.severity)
        sev_run.bold = True
        sev_run.font.color.rgb = _SEVERITY_COLORS.get(vuln.severity, RGBColor(0, 0, 0))

        document.add_paragraph(f"CVSS Score: {vuln.cvss_score}")
        document.add_paragraph(f"CVSS Vector: {vuln.cvss_vector}")

        document.add_heading("Description", level=4)
        document.add_paragraph(vuln.description)

        document.add_heading("Evidence", level=4)
        for step_idx, step in enumerate(evidence_steps_by_vuln_id.get(vuln.id, []), 1):
            document.add_paragraph(f"Step {step_idx}: {step.comment}")
            for object_key in step.screenshot_object_keys:
                image_bytes = screenshot_bytes_by_object_key.get(object_key)
                if image_bytes:
                    try:
                        document.add_picture(io.BytesIO(image_bytes), width=Inches(4))
                    except Exception:  # noqa: BLE001 — a corrupt evidence image must not break the report
                        document.add_paragraph(f"[Invalid image: {object_key}]")
                else:
                    document.add_paragraph(f"[Image not found: {object_key}]")

        document.add_heading("Recommendation", level=4)
        document.add_paragraph(vuln.recommendation)
        document.add_heading("Reference", level=4)
        document.add_paragraph(vuln.reference)

    buffer = io.BytesIO()
    document.save(buffer)
    return buffer.getvalue()
