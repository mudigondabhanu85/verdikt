import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_finding_or_404, write_audit_log
from app.auth.rbac import require_permission
from app.db.session import get_db_session
from app.integrations.jira.client import JiraClient, JiraTicketError
from app.models.finding import Finding
from app.models.finding_ticket import FindingTicket
from app.models.organization import User
from app.models.ticketing_config import TicketingConfig
from app.schemas.finding_ticket import FindingTicketCreate, FindingTicketOut
from app.vault.credential_vault import decrypt_secret

router = APIRouter(tags=["finding-tickets"])


def _issue_description(finding: Finding) -> str:
    endpoints = ", ".join(finding.affected_endpoints)
    return (
        f"{finding.plain_language_summary}\n\n"
        f"Technical detail: {finding.technical_description}\n\n"
        f"Affected endpoint(s): {endpoints}\n\n"
        f"Remediation: {finding.remediation}\n\n"
        f"Severity: {finding.severity} (CVSS {finding.cvss_score}, {finding.cwe_id})\n"
        f"Filed from Verdikt finding {finding.id}."
    )


@router.post("/findings/{finding_id}/tickets", response_model=FindingTicketOut, status_code=201)
async def create_finding_ticket(
    finding_id: uuid.UUID,
    payload: FindingTicketCreate,
    user: User = Depends(require_permission("scan", "create")),
    session: AsyncSession = Depends(get_db_session),
) -> FindingTicket:
    finding = await get_finding_or_404(session, finding_id, user.org_id)

    config = await session.get(TicketingConfig, payload.ticketing_config_id)
    if config is None or config.org_id != user.org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Ticketing config not found")

    client = JiraClient(config.base_url, config.email, decrypt_secret(config.encrypted_api_token))
    try:
        issue = await client.create_issue(
            project_key=config.project_key,
            issue_type=config.issue_type,
            summary=f"[{finding.severity}] {finding.title}",
            description=_issue_description(finding),
        )
    except JiraTicketError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc

    ticket = FindingTicket(
        finding_id=finding.id,
        ticketing_config_id=config.id,
        created_by=user.id,
        external_key=issue["key"],
        external_url=issue["url"],
    )
    session.add(ticket)
    await write_audit_log(
        session,
        user=user,
        action="finding.create_ticket",
        resource_type="organization",
        resource_id=user.org_id,
        metadata={"finding_id": str(finding.id), "external_key": issue["key"]},
    )
    await session.commit()
    await session.refresh(ticket)
    return ticket


@router.get("/findings/{finding_id}/tickets", response_model=list[FindingTicketOut])
async def list_finding_tickets(
    finding_id: uuid.UUID,
    user: User = Depends(require_permission("scan", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> list[FindingTicket]:
    await get_finding_or_404(session, finding_id, user.org_id)
    result = await session.execute(select(FindingTicket).where(FindingTicket.finding_id == finding_id))
    return list(result.scalars().all())
