"""Word (.docx) report export (§8) via python-docx — pure Python, no
native dependency. Same content as the HTML/PDF reports: executive
summary, severity summary table, and one section per finding.
"""

import io
import uuid

from docx import Document
from docx.enum.text import WD_COLOR_INDEX
from docx.shared import Inches, Pt, RGBColor

from app.models.attack_chain import AttackChain
from app.models.finding import Finding
from app.reporting.grouping import group_findings
from app.reporting.html_report import BrandingInfo
from app.reporting.payload_highlight import find_highlight_match
from app.schemas.scan import ScanRunDetail

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
SEVERITY_RGB = {
    "Critical": RGBColor(0x7F, 0x1D, 0x1D),
    "High": RGBColor(0xB9, 0x1C, 0x1C),
    "Medium": RGBColor(0xB4, 0x53, 0x09),
    "Low": RGBColor(0x25, 0x63, 0xEB),
}

_MAX_EVIDENCE_CHARS = 3000
_NO_VISUAL_POC_NOTE = (
    "No visual proof-of-concept for this finding — it's based on HTTP headers/protocol "
    "behavior with nothing meaningful to render as a screenshot; see the request/response "
    "evidence above instead."
)


def _mono_run(paragraph, text: str, *, highlighted: bool = False):
    run = paragraph.add_run(text)
    run.font.name = "Courier New"
    run.font.size = Pt(8)
    if highlighted:
        run.font.highlight_color = WD_COLOR_INDEX.YELLOW
    return run


def _mono_paragraph(document: Document, text: str, *, payload: str | None = None) -> None:
    """Same monospace evidence paragraph as before, split into multiple
    runs around every occurrence of the matched highlight candidate (see
    app.reporting.payload_highlight — the exact substring that proves
    the finding may be the literal Evidence.payload, its form-encoded
    form, or an embedded marker token) so that substring alone gets a
    highlight run, the DOCX-native equivalent of the HTML report's
    <mark> tag. Falls back to one plain run, unchanged from before this
    existed, when there's no payload or no candidate is present in this
    particular text.
    """
    text = (text or "")[:_MAX_EVIDENCE_CHARS]
    paragraph = document.add_paragraph()
    match = find_highlight_match(text, payload)
    if match is None:
        _mono_run(paragraph, text)
        return
    parts = text.split(match)
    for i, part in enumerate(parts):
        if part:
            _mono_run(paragraph, part)
        if i < len(parts) - 1:
            _mono_run(paragraph, match, highlighted=True)


def render_docx_report(
    *,
    scan_run: ScanRunDetail,
    findings: list[Finding],
    executive_summary: str,
    screenshots_by_finding_id: dict[uuid.UUID, list[bytes]] | None = None,
    attack_chains: list[AttackChain] | None = None,
    branding: BrandingInfo | None = None,
) -> bytes:
    screenshots_by_finding_id = screenshots_by_finding_id or {}
    attack_chains = attack_chains or []
    groups = group_findings(findings)
    document = Document()

    if branding and branding.logo_bytes:
        try:
            document.add_picture(io.BytesIO(branding.logo_bytes), width=Inches(1.5))
        except Exception:  # noqa: BLE001 — a corrupt/unreadable logo must not break report generation
            pass

    title = "Verdikt Security Assessment Report"
    if branding and branding.company_name:
        title = f"{branding.company_name} — {title}"
    document.add_heading(title, level=1)
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

    if attack_chains:
        document.add_heading("Attack Chains", level=2)
        document.add_paragraph(
            "These findings, individually Confirmed elsewhere in this report, combine into "
            "a worse compound exploit — a real attacker chaining them together achieves more "
            "than any single finding suggests. Each chain listed here has independently "
            "passed the same Confirmed-Only adversarial-validation discipline as every other "
            "finding in this report."
        )
        for chain in attack_chains:
            heading = document.add_heading(level=3)
            run = heading.add_run(f"[{chain.severity}] {chain.title}")
            run.font.color.rgb = SEVERITY_RGB.get(chain.severity, RGBColor(0, 0, 0))
            meta = document.add_paragraph()
            meta.add_run(f"Links {len(chain.finding_ids)} findings").italic = True
            document.add_heading("What this means", level=4)
            document.add_paragraph(chain.plain_language_summary)
            document.add_heading("Narrative", level=4)
            document.add_paragraph(chain.narrative)
            if chain.steps_to_reproduce:
                document.add_heading("Steps to reproduce (end-to-end)", level=4)
                for step in chain.steps_to_reproduce:
                    document.add_paragraph(step, style="List Number")

    document.add_heading("Findings", level=2)
    if not groups:
        document.add_paragraph("No confirmed findings for this scan run.")
    else:
        document.add_paragraph(
            f"{len(findings)} confirmed finding{'' if len(findings) == 1 else 's'} across "
            f"{len(groups)} vulnerability type{'' if len(groups) == 1 else 's'}."
        )

    # One heading (+ shared narrative) per (check_id, title) GROUP, not
    # per raw Finding row — see app.reporting.grouping's docstring: a
    # scan commonly confirms the same check across dozens of endpoints,
    # and one full section per occurrence produced reports hundreds of
    # pages long with near-duplicate content (a real 291-finding scan
    # produced a 629-page PDF; this document had the same problem).
    for group in groups:
        shared = group.shared
        document.add_page_break()
        heading = document.add_heading(level=2)
        run = heading.add_run(
            f"[{group.severity}] {group.title} "
            f"({len(group.instances)} instance{'' if len(group.instances) == 1 else 's'})"
        )
        run.font.color.rgb = SEVERITY_RGB.get(group.severity, RGBColor(0, 0, 0))

        meta = document.add_paragraph()
        meta.add_run(f"{shared.owasp_2025_category} | {shared.cwe_id}").italic = True

        document.add_heading("What this means", level=3)
        document.add_paragraph(shared.plain_language_summary)

        document.add_heading("Technical detail", level=3)
        document.add_paragraph(shared.technical_description)

        document.add_heading("Remediation", level=3)
        document.add_paragraph(shared.remediation)

        if shared.references:
            document.add_heading("References", level=3)
            for ref in shared.references:
                document.add_paragraph(ref, style="List Bullet")

        document.add_heading("Instances", level=3)
        for idx, instance in enumerate(group.detailed_instances, start=1):
            endpoint = instance.affected_endpoints[0] if instance.affected_endpoints else "(no endpoint recorded)"
            p = document.add_paragraph()
            p.add_run(f"{idx}. ").bold = True
            p.add_run(f"{endpoint} — CVSS {instance.cvss_score} ({instance.cvss_vector})")

            if instance.affected_endpoints:
                for endpoint in instance.affected_endpoints:
                    document.add_paragraph(endpoint, style="List Bullet")

            if instance.steps_to_reproduce:
                for step in instance.steps_to_reproduce:
                    document.add_paragraph(step, style="List Number")

            if instance.evidence:
                _mono_paragraph(document, "Request:")
                _mono_paragraph(document, instance.evidence.request_raw, payload=instance.evidence.payload)
                _mono_paragraph(document, "Response:")
                _mono_paragraph(document, instance.evidence.response_raw, payload=instance.evidence.payload)

            screenshots = screenshots_by_finding_id.get(instance.id, [])
            any_screenshot_embedded = False
            for image_bytes in screenshots:
                try:
                    document.add_heading("Evidence — screenshot", level=4)
                    document.add_picture(io.BytesIO(image_bytes), width=Inches(5))
                    any_screenshot_embedded = True
                except Exception:  # noqa: BLE001 — a corrupt/unreadable image must not break report generation
                    document.add_paragraph("(screenshot could not be embedded)")

            if not any_screenshot_embedded:
                note = document.add_paragraph()
                run = note.add_run(_NO_VISUAL_POC_NOTE)
                run.italic = True
                run.font.color.rgb = RGBColor(0x55, 0x55, 0x55)
                run.font.size = Pt(9)

        remaining = group.summary_only_instances
        if remaining:
            document.add_paragraph(
                f"Also confirmed at {len(remaining)} more endpoint"
                f"{'' if len(remaining) == 1 else 's'} (full evidence shown above is "
                "representative and applies identically):"
            )
            for instance in remaining:
                endpoint = instance.affected_endpoints[0] if instance.affected_endpoints else "(no endpoint recorded)"
                document.add_paragraph(endpoint, style="List Bullet")

    buffer = io.BytesIO()
    document.save(buffer)
    return buffer.getvalue()
