from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.models.finding import Finding
from app.schemas.scan import ScanRunDetail

_env = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "templates"),
    autoescape=select_autoescape(["html"]),
)

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def render_html_report(*, scan_run: ScanRunDetail, findings: list[Finding]) -> str:
    """Basic HTML report (roadmap Phase 1 scope — Word/PDF/dual-audience
    polish is Phase 5). Still includes a minimal "how to read this report"
    section and plain-language summaries per §8, since that's cheap and
    directly requested even at this basic level.
    """
    ordered = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    template = _env.get_template("report.html.jinja")
    return template.render(scan_run=scan_run, findings=ordered)
