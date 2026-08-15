import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_version_or_404, write_audit_log
from app.auth.rbac import require_permission
from app.db.session import get_db_session
from app.models.business_rule import BusinessRule
from app.models.organization import User
from app.schemas.business_rule import BusinessRuleCreate, BusinessRuleOut

router = APIRouter(prefix="/versions/{version_id}/business-rules", tags=["business-rules"])


@router.post("", response_model=BusinessRuleOut, status_code=201)
async def create_business_rule(
    version_id: uuid.UUID,
    payload: BusinessRuleCreate,
    user: User = Depends(require_permission("business_rule", "create")),
    session: AsyncSession = Depends(get_db_session),
) -> BusinessRule:
    await get_version_or_404(session, version_id, user.org_id)
    rule = BusinessRule(
        version_id=version_id,
        rule_type=payload.rule_type,
        title=payload.title,
        config=payload.config,
        created_by=user.id,
    )
    session.add(rule)
    await write_audit_log(
        session,
        user=user,
        action="business_rule.create",
        resource_type="version",
        resource_id=version_id,
        metadata={"rule_type": payload.rule_type, "title": payload.title},
    )
    await session.commit()
    await session.refresh(rule)
    return rule


@router.get("", response_model=list[BusinessRuleOut])
async def list_business_rules(
    version_id: uuid.UUID,
    user: User = Depends(require_permission("business_rule", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> list[BusinessRule]:
    await get_version_or_404(session, version_id, user.org_id)
    result = await session.execute(select(BusinessRule).where(BusinessRule.version_id == version_id))
    return list(result.scalars().all())


@router.delete("/{rule_id}", status_code=204)
async def delete_business_rule(
    version_id: uuid.UUID,
    rule_id: uuid.UUID,
    user: User = Depends(require_permission("business_rule", "delete")),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    await get_version_or_404(session, version_id, user.org_id)
    rule = await session.get(BusinessRule, rule_id)
    if rule is None or rule.version_id != version_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Business rule not found")
    await write_audit_log(
        session,
        user=user,
        action="business_rule.delete",
        resource_type="version",
        resource_id=version_id,
        metadata={"title": rule.title},
    )
    await session.delete(rule)
    await session.commit()
