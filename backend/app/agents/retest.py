"""Retest/diff workflow (§8, deferred from Phase 5, built in Phase 6):
re-runs a scan against the same Version and diffs the new findings
against a prior run's, so Finding.retest_status (open/fixed/
risk_accepted/false_positive_after_review — modeled in the schema since
Phase 1 but never actually set until now) reflects what changed between
two scans.
"""

import uuid

from sqlalchemy import select

from app.agents.runner import execute_scan_run
from app.db import session as db_session
from app.models.finding import Finding

# retest_status values an analyst set explicitly — a rescan diff must
# never silently overwrite a human risk decision.
_ANALYST_LOCKED_STATUSES = ("risk_accepted", "false_positive_after_review")


def _match_key(finding: Finding) -> tuple[str, frozenset[str]]:
    return (finding.check_id, frozenset(finding.affected_endpoints))


async def execute_retest(new_scan_run_id: uuid.UUID, prior_scan_run_id: uuid.UUID) -> None:
    """Invoked by FastAPI BackgroundTasks (app.api.routes.scans.retest_scan_run).
    Runs the new scan to completion first (via the same execute_scan_run
    used for a regular scan run — a retest IS a regular scan, just one
    with a diff step tacked on afterward), then diffs.
    """
    await execute_scan_run(new_scan_run_id)

    adapter = db_session.get_adapter()
    async with db_session.session_scope(adapter) as session:
        prior_findings = list(
            (
                await session.execute(select(Finding).where(Finding.scan_run_id == prior_scan_run_id))
            ).scalars()
        )
        new_findings = list(
            (
                await session.execute(select(Finding).where(Finding.scan_run_id == new_scan_run_id))
            ).scalars()
        )
        new_keys = {_match_key(f) for f in new_findings}

        for prior in prior_findings:
            if prior.retest_status in _ANALYST_LOCKED_STATUSES:
                continue
            prior.retest_status = "open" if _match_key(prior) in new_keys else "fixed"

        await session.commit()
