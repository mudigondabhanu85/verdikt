"""§8 reporting/ops gap — posts a Slack message when a scan run reaches
a terminal state, if the org has an active NotificationConfig. Best-
effort by design: a broken/unreachable webhook must never fail the scan
itself, so every failure here is caught and swallowed after one attempt
— there's no retry queue for this first pass.
"""

from collections import Counter

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding
from app.models.notification_config import NotificationConfig
from app.models.project import Project, Version
from app.models.scan import ScanRun
from app.notifications.dispatch import NotificationDispatchError, send_notification


def _summary_text(scan_run: ScanRun, counts: Counter) -> str:
    severity_bits = ", ".join(f"{sev}: {counts.get(sev, 0)}" for sev in ("Critical", "High", "Medium", "Low"))
    return (
        f"Verdikt scan {scan_run.status} for version {scan_run.version_id}.\n"
        f"Findings — {severity_bits}."
    )


async def notify_scan_completed(session: AsyncSession, scan_run: ScanRun) -> None:
    version = await session.get(Version, scan_run.version_id)
    if version is None:
        return
    project = await session.get(Project, version.project_id)
    if project is None:
        return

    configs = list(
        (
            await session.execute(
                select(NotificationConfig).where(
                    NotificationConfig.org_id == project.org_id,
                    NotificationConfig.notify_on_scan_completed.is_(True),
                )
            )
        ).scalars()
    )
    if not configs:
        return

    findings = list(
        (await session.execute(select(Finding.severity).where(Finding.scan_run_id == scan_run.id))).scalars()
    )
    counts = Counter(findings)
    text = _summary_text(scan_run, counts)

    for config in configs:
        try:
            await send_notification(config, text)
        except NotificationDispatchError:
            # Best-effort — a broken webhook/SMTP config must never fail
            # the scan itself. An analyst debugging a silent notification
            # would use the "test" endpoint
            # (app.api.routes.notification_configs) rather than relying on
            # scan-run failure to surface this.
            continue
