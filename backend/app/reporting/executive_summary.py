"""LLM-generated executive summary for a scan run's report (§8). Purely
descriptive of already-confirmed findings — it never adds, removes, or
reclassifies a finding, so it can't undermine §2's Confirmed-Only
Findings Policy. Its cost counts against the same per-scan-run LLM
budget (§10.5) as the scan's own agents, via the same BudgetGuard.
"""

from app.ai.adapters.null import NullAIProviderAdapter
from app.ai.budget import BudgetExceededError, BudgetGuard, ProviderUnavailableError
from app.ai.prompts.loader import render_prompt
from app.models.finding import Finding
from app.schemas.scan import ScanRunDetail

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

_FALLBACK_NO_FINDINGS = (
    "No confirmed findings were produced by this scan run. This does not by "
    "itself guarantee the target is free of vulnerabilities — it reflects only "
    "what this engagement's automated checks were able to independently confirm "
    "within its configured scope and budget."
)


def _fallback_summary(findings: list[Finding]) -> str:
    """Deterministic, zero-cost summary — used when no real AI provider is
    configured (settings.ai_provider == "fake") so a report never embeds
    the Null adapter's placeholder JSON as if it were prose, and used as
    a safety net if the LLM call fails or returns an empty response.
    """
    if not findings:
        return _FALLBACK_NO_FINDINGS

    ordered = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    breakdown = ", ".join(
        f"{counts[sev]} {sev.lower()}" for sev in ("Critical", "High", "Medium", "Low") if counts.get(sev)
    )
    worst = ordered[0]
    return (
        f"This engagement confirmed {len(findings)} finding(s): {breakdown}. "
        f'The most severe is "{worst.title}" ({worst.severity} severity). '
        "Findings are detailed below with reproduction steps and remediation "
        "guidance — addressing Critical and High severity items first is recommended."
    )


async def generate_executive_summary(
    *,
    scan_run: ScanRunDetail,
    findings: list[Finding],
    budget_guard: BudgetGuard,
    ai_model: str,
) -> str:
    if isinstance(budget_guard.provider, NullAIProviderAdapter):
        # No real provider configured (neither a deployment-wide one nor
        # a per-scan-run AIProviderConfig) — don't call an adapter whose
        # only possible response is a fixed placeholder JSON string.
        return _fallback_summary(findings)

    ordered = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    top_findings = (
        "\n".join(
            f"- {f.title} — {f.severity} — {f.technical_description[:200]}"
            for f in ordered[:5]
        )
        or "(none)"
    )
    severity_breakdown = ", ".join(
        f"{sev}: {scan_run.finding_counts_by_severity.get(sev, 0)}"
        for sev in ("Critical", "High", "Medium", "Low")
    )

    messages = render_prompt(
        "executive_summary",
        status=scan_run.status,
        total_findings=str(len(findings)),
        severity_breakdown=severity_breakdown,
        top_findings=top_findings,
    )
    try:
        response = await budget_guard.guarded_complete(messages, model=ai_model, max_tokens=400)
    except (BudgetExceededError, ProviderUnavailableError):
        return _fallback_summary(findings)

    return response.content.strip() or _fallback_summary(findings)
