import base64
import uuid
from dataclasses import dataclass
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from app.models.attack_chain import AttackChain
from app.models.finding import Finding
from app.reporting.grouping import group_findings
from app.schemas.scan import ScanRunDetail


@dataclass
class BrandingInfo:
    """Report-layer view of app.models.org_branding.OrgBranding — a plain
    dataclass rather than the ORM model directly, so the reporting layer
    doesn't depend on the DB layer. Callers (the report.* API routes)
    build this from the real OrgBranding row plus the logo bytes fetched
    from object storage.
    """

    company_name: str | None = None
    primary_color_hex: str | None = None
    logo_bytes: bytes | None = None
    logo_content_type: str = "image/png"

_env = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "templates"),
    # autoescape=True unconditionally, not select_autoescape(["html"]) —
    # the latter matches by template *filename* extension, and this
    # template is named "report.html.jinja" (ends in ".jinja", not
    # ".html"), so select_autoescape silently left autoescaping off.
    # Finding fields (title, technical_description, evidence, ...) can
    # contain attacker-influenced text (e.g. a reflected-XSS payload
    # captured as evidence) — this report must never re-render that
    # unescaped into an HTML document someone opens in a browser.
    autoescape=True,
)


def render_html_report(
    *,
    scan_run: ScanRunDetail,
    findings: list[Finding],
    executive_summary: str | None = None,
    screenshots_by_finding_id: dict[uuid.UUID, list[bytes]] | None = None,
    attack_chains: list[AttackChain] | None = None,
    branding: BrandingInfo | None = None,
) -> str:
    """HTML report (§8): "how to read this report" section, an
    LLM-generated executive summary (app.reporting.executive_summary),
    plain-language + technical dual-audience findings, and any captured
    browser-proof screenshots (app.reporting.screenshots) embedded inline
    as base64 data URIs — keeps the report a single self-contained file.
    """
    finding_groups = group_findings(findings)
    screenshots_by_finding_id = screenshots_by_finding_id or {}
    screenshots_b64 = {
        finding_id: [base64.b64encode(img).decode("ascii") for img in images]
        for finding_id, images in screenshots_by_finding_id.items()
    }
    branding_ctx = None
    if branding is not None:
        branding_ctx = {
            "company_name": branding.company_name,
            "primary_color_hex": branding.primary_color_hex,
            "logo_data_uri": (
                f"data:{branding.logo_content_type};base64,"
                f"{base64.b64encode(branding.logo_bytes).decode('ascii')}"
                if branding.logo_bytes
                else None
            ),
        }

    template = _env.get_template("report.html.jinja")
    return template.render(
        scan_run=scan_run,
        finding_groups=finding_groups,
        total_finding_count=len(findings),
        executive_summary=executive_summary,
        screenshots_by_finding_id=screenshots_b64,
        attack_chains=attack_chains or [],
        branding=branding_ctx,
    )
