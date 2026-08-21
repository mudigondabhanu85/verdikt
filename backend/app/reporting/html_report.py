from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from app.models.finding import Finding
from app.schemas.scan import ScanRunDetail

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

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def render_html_report(
    *, scan_run: ScanRunDetail, findings: list[Finding], executive_summary: str | None = None
) -> str:
    """HTML report (§8): "how to read this report" section, an
    LLM-generated executive summary (app.reporting.executive_summary),
    and plain-language + technical dual-audience findings.
    """
    ordered = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    template = _env.get_template("report.html.jinja")
    return template.render(scan_run=scan_run, findings=ordered, executive_summary=executive_summary)
