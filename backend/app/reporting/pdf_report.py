"""PDF report export (§8) via reportlab — pure Python, no native
dependency (WeasyPrint's Pango/Cairo requirement wasn't satisfiable in
the build sandbox, see the Phase 5 planning notes). Same content as the
HTML report (app.reporting.html_report): executive summary, severity
summary table, and one section per finding with plain-language +
technical descriptions, reproduction steps, remediation, and evidence.
"""

import io
import uuid

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.lib.utils import ImageReader
from reportlab.platypus import (
    Image,
    ListFlowable,
    ListItem,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.models.attack_chain import AttackChain
from app.models.finding import Finding
from app.reporting.grouping import group_findings
from app.reporting.html_report import BrandingInfo
from app.schemas.scan import ScanRunDetail

_MAX_IMAGE_WIDTH = 5 * inch
_MAX_IMAGE_HEIGHT = 6 * inch

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


def _image_flowable(png_bytes: bytes) -> Image | None:
    try:
        reader = ImageReader(io.BytesIO(png_bytes))
        natural_width, natural_height = reader.getSize()
    except Exception:  # noqa: BLE001 — a corrupt/unreadable image must not break report generation
        return None
    if not natural_width or not natural_height:
        return None
    scale = min(1.0, _MAX_IMAGE_WIDTH / natural_width, _MAX_IMAGE_HEIGHT / natural_height)
    return Image(io.BytesIO(png_bytes), width=natural_width * scale, height=natural_height * scale)


def render_pdf_report(
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
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=LETTER, title="Verdikt Security Assessment Report")
    story: list = []

    if branding and branding.logo_bytes:
        logo_flowable = _image_flowable(branding.logo_bytes)
        if logo_flowable is not None:
            story.append(logo_flowable)
            story.append(Spacer(1, 8))

    title_text = "Verdikt Security Assessment Report"
    if branding and branding.company_name:
        title_text = f"{_escape(branding.company_name)} — {title_text}"
    story.append(Paragraph(title_text, _h1))
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

    if attack_chains:
        story.append(Paragraph("Attack Chains", _h2))
        story.append(
            Paragraph(
                "These findings, individually Confirmed elsewhere in this report, combine "
                "into a worse compound exploit — a real attacker chaining them together "
                "achieves more than any single finding suggests. Each chain listed here has "
                "independently passed the same Confirmed-Only adversarial-validation "
                "discipline as every other finding in this report.",
                _body,
            )
        )
        for chain in attack_chains:
            color_hex = SEVERITY_HEX.get(chain.severity, "#000000")
            story.append(
                Paragraph(
                    f'<font color="{color_hex}">[{chain.severity}]</font> {_escape(chain.title)}',
                    _h3,
                )
            )
            story.append(
                Paragraph(f"Links {len(chain.finding_ids)} findings", _body)
            )
            story.append(Paragraph("What this means", _h3))
            story.append(Paragraph(_escape(chain.plain_language_summary), _body))
            story.append(Paragraph("Narrative", _h3))
            story.append(Paragraph(_escape(chain.narrative), _body))
            if chain.steps_to_reproduce:
                story.append(Paragraph("Steps to reproduce (end-to-end)", _h3))
                story.append(
                    ListFlowable(
                        [ListItem(Paragraph(_escape(s), _body)) for s in chain.steps_to_reproduce],
                        bulletType="1",
                    )
                )
        story.append(Spacer(1, 12))

    story.append(Paragraph("Findings", _h2))
    if not groups:
        story.append(Paragraph("No confirmed findings for this scan run.", _body))
    else:
        story.append(
            Paragraph(
                f"{len(findings)} confirmed finding{'' if len(findings) == 1 else 's'} across "
                f"{len(groups)} vulnerability type{'' if len(groups) == 1 else 's'}.",
                _body,
            )
        )

    # One heading (+ shared narrative) per (check_id, title) GROUP, not
    # per raw Finding row — a scan commonly confirms the same check
    # across dozens of endpoints (e.g. a missing header on every crawled
    # page), and one full page per occurrence produced reports hundreds
    # of pages long with near-duplicate content (a real 291-finding scan
    # produced a 629-page PDF). plain_language_summary/technical_description/
    # remediation are identical across a group's instances (see
    # app.reporting.grouping's docstring) — rendered once via
    # `group.shared`, with only the per-instance specifics (endpoint,
    # steps, evidence) repeated per instance.
    for group in groups:
        story.append(PageBreak())
        shared = group.shared
        color_hex = SEVERITY_HEX.get(group.severity, "#000000")
        story.append(
            Paragraph(
                f'<font color="{color_hex}">[{group.severity}]</font> {_escape(group.title)} '
                f"({len(group.instances)} instance{'' if len(group.instances) == 1 else 's'})",
                _h2,
            )
        )
        story.append(
            Paragraph(
                f"{_escape(shared.owasp_2025_category)} | {_escape(shared.cwe_id)}",
                _body,
            )
        )
        story.append(Spacer(1, 6))

        story.append(Paragraph("What this means", _h3))
        story.append(Paragraph(_escape(shared.plain_language_summary), _body))

        story.append(Paragraph("Technical detail", _h3))
        story.append(Paragraph(_escape(shared.technical_description), _body))

        story.append(Paragraph("Remediation", _h3))
        story.append(Paragraph(_escape(shared.remediation), _body))

        if shared.references:
            story.append(Paragraph("References", _h3))
            story.append(
                ListFlowable(
                    [ListItem(Paragraph(_escape(r), _body)) for r in shared.references],
                    bulletType="bullet",
                )
            )

        story.append(Paragraph("Instances", _h3))
        for idx, instance in enumerate(group.detailed_instances, start=1):
            endpoint = instance.affected_endpoints[0] if instance.affected_endpoints else "(no endpoint recorded)"
            story.append(
                Paragraph(
                    f"<b>{idx}.</b> <font face=\"Courier\">{_escape(endpoint)}</font> — "
                    f"CVSS {instance.cvss_score} ({_escape(instance.cvss_vector)})",
                    _body,
                )
            )

            if instance.affected_endpoints:
                story.append(
                    ListFlowable(
                        [ListItem(Paragraph(_escape(e), _mono)) for e in instance.affected_endpoints],
                        bulletType="bullet",
                    )
                )

            if instance.steps_to_reproduce:
                story.append(
                    ListFlowable(
                        [ListItem(Paragraph(_escape(s), _body)) for s in instance.steps_to_reproduce],
                        bulletType="1",
                    )
                )

            if instance.evidence:
                story.append(Paragraph("Evidence — request", _mono))
                story.append(Paragraph(_escape_pre(instance.evidence.request_raw), _mono))
                story.append(Paragraph("Evidence — response", _mono))
                story.append(Paragraph(_escape_pre(instance.evidence.response_raw), _mono))

            for image_bytes in screenshots_by_finding_id.get(instance.id, []):
                flowable = _image_flowable(image_bytes)
                if flowable is not None:
                    story.append(Paragraph("Evidence — screenshot", _mono))
                    story.append(flowable)

            story.append(Spacer(1, 10))

        remaining = group.summary_only_instances
        if remaining:
            story.append(
                Paragraph(
                    f"Also confirmed at {len(remaining)} more endpoint"
                    f"{'' if len(remaining) == 1 else 's'} (full evidence shown above is "
                    "representative and applies identically):",
                    _body,
                )
            )
            story.append(
                ListFlowable(
                    [
                        ListItem(
                            Paragraph(
                                _escape(
                                    instance.affected_endpoints[0]
                                    if instance.affected_endpoints
                                    else "(no endpoint recorded)"
                                ),
                                _mono,
                            )
                        )
                        for instance in remaining
                    ],
                    bulletType="bullet",
                )
            )
            story.append(Spacer(1, 10))

    doc.build(story)
    return buffer.getvalue()
