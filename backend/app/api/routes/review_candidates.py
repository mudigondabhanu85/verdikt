import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.xss import XSS_FINDING_METADATA
from app.api.deps import get_review_candidate_or_404, get_scan_run_or_404, write_audit_log
from app.auth.rbac import require_permission
from app.db.session import get_db_session
from app.models.finding import Evidence, Finding
from app.models.organization import User
from app.models.review_candidate import ReviewCandidate
from app.schemas.finding import FindingOut
from app.schemas.review_candidate import ReviewCandidateOut

router = APIRouter(tags=["review-candidates"])

# Finding metadata for promoting a candidate (§2 step 5). check_type ==
# "xss-reflected" is the only producer today (app/agents/xss.py) — a new
# XSS-adjacent check type needs an entry here before it can be promoted.
# Shares its taxonomy entry (OWASP/CWE/CVSS/remediation) with the
# browser-proof auto-confirmation path in app.agents.xss — same
# vulnerability class either way.
_PROMOTION_METADATA = {
    "xss-reflected": {
        **XSS_FINDING_METADATA,
        "plain_language_summary": (
            "An analyst manually reviewed and confirmed this reflected XSS finding. "
            "It was flagged by the automated scanner but required human/browser "
            "verification before being promoted to a confirmed finding."
        ),
    }
}


@router.get("/scan-runs/{scan_run_id}/review-candidates", response_model=list[ReviewCandidateOut])
async def list_review_candidates(
    scan_run_id: uuid.UUID,
    user: User = Depends(require_permission("review_candidate", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> list[ReviewCandidate]:
    await get_scan_run_or_404(session, scan_run_id, user.org_id)
    result = await session.execute(
        select(ReviewCandidate).where(ReviewCandidate.scan_run_id == scan_run_id)
    )
    return list(result.scalars().all())


@router.post("/review-candidates/{candidate_id}/promote", response_model=FindingOut, status_code=201)
async def promote_review_candidate(
    candidate_id: uuid.UUID,
    user: User = Depends(require_permission("review_candidate", "update")),
    session: AsyncSession = Depends(get_db_session),
) -> Finding:
    """§2 step 5: an analyst-reviewed candidate becomes a real Finding,
    flagged analyst_confirmed (not ai_confirmed) since it reached this
    state via human judgment, not the automated pipeline alone."""
    candidate = await get_review_candidate_or_404(session, candidate_id, user.org_id)
    if candidate.status != "pending":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Candidate already {candidate.status}")

    meta = _PROMOTION_METADATA.get(candidate.check_type)
    if meta is None:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, f"No promotion metadata for check type {candidate.check_type!r}"
        )

    finding = Finding(
        scan_run_id=candidate.scan_run_id,
        agent_job_id=candidate.agent_job_id,
        check_id=candidate.check_type,
        title=candidate.title,
        severity=candidate.severity_guess,
        owasp_2025_category=meta["owasp_2025_category"],
        cwe_id=meta["cwe_id"],
        portswigger_reference_url=meta["portswigger_reference_url"],
        cvss_vector=meta["cvss_vector"],
        cvss_score=meta["cvss_score"],
        affected_endpoints=[candidate.affected_endpoint],
        plain_language_summary=meta["plain_language_summary"],
        technical_description=(
            f"Promoted by an analyst from an automated review candidate. Original AI "
            f"triage reasoning: {candidate.llm_reasoning}"
        ),
        steps_to_reproduce=[
            f"1. Send the request captured in this finding's evidence to {candidate.affected_endpoint}.",
            "2. Reproduce in a browser and confirm the payload actually executes.",
        ],
        remediation=meta["remediation"],
        references=[meta["portswigger_reference_url"]],
        confirmation_status="analyst_confirmed",
    )
    session.add(finding)
    await session.flush()
    session.add(
        Evidence(
            finding_id=finding.id, request_raw=candidate.request_raw, response_raw=candidate.response_raw
        )
    )
    candidate.status = "promoted"
    await write_audit_log(
        session,
        user=user,
        action="review_candidate.promote",
        resource_type="review_candidate",
        resource_id=candidate.id,
    )
    await session.commit()
    await session.refresh(finding, attribute_names=["evidence"])
    return finding


@router.post("/review-candidates/{candidate_id}/dismiss", response_model=ReviewCandidateOut)
async def dismiss_review_candidate(
    candidate_id: uuid.UUID,
    user: User = Depends(require_permission("review_candidate", "update")),
    session: AsyncSession = Depends(get_db_session),
) -> ReviewCandidate:
    candidate = await get_review_candidate_or_404(session, candidate_id, user.org_id)
    if candidate.status != "pending":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Candidate already {candidate.status}")

    candidate.status = "dismissed"
    await write_audit_log(
        session,
        user=user,
        action="review_candidate.dismiss",
        resource_type="review_candidate",
        resource_id=candidate.id,
    )
    await session.commit()
    await session.refresh(candidate)
    return candidate
