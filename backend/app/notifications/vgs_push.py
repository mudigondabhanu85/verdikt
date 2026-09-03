"""§11 — pushes a scan run's confirmed findings to VGS (the user's
existing DAST governance tool) when the scan reaches a terminal state,
if the org has an active VGSConfig. Decoupled integration path per §11:
VGS stays the system of record for governance/remediation tracking,
this just pushes structured findings (JSON, tagged source:
ai-multi-agent) to its ingestion webhook. Best-effort by design, same
reasoning as app.notifications.scan_notifications — a broken/
unreachable webhook must never fail the scan itself.
"""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.integrations.vgs.client import VGSClient, VGSPushError
from app.models.finding import Finding
from app.models.project import Project, Version
from app.models.scan import ScanRun
from app.models.vgs_config import VGSConfig
from app.schemas.finding import FindingOut
from app.vault.credential_vault import decrypt_secret


async def push_findings_to_vgs(session: AsyncSession, scan_run: ScanRun) -> None:
    version = await session.get(Version, scan_run.version_id)
    if version is None:
        return
    project = await session.get(Project, version.project_id)
    if project is None:
        return

    configs = list(
        (
            await session.execute(
                select(VGSConfig).where(
                    VGSConfig.org_id == project.org_id,
                    VGSConfig.push_on_scan_completed.is_(True),
                )
            )
        ).scalars()
    )
    if not configs:
        return

    findings = list(
        (
            await session.execute(
                select(Finding)
                .where(Finding.scan_run_id == scan_run.id)
                .options(selectinload(Finding.evidence))
            )
        ).scalars()
    )
    findings_payload = [FindingOut.model_validate(f).model_dump(mode="json") for f in findings]

    for config in configs:
        webhook_url = decrypt_secret(config.encrypted_webhook_url)
        client = VGSClient(webhook_url)
        try:
            await client.push_findings(str(scan_run.id), findings_payload)
        except VGSPushError:
            # Best-effort — a broken webhook must never fail the scan
            # itself. An analyst debugging a silent push failure would
            # use the "test" endpoint (app.api.routes.vgs_configs)
            # rather than relying on scan-run failure to surface this.
            continue
