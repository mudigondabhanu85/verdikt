import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import write_audit_log
from app.auth.oidc import (
    OidcError,
    OidcIdentity,
    build_authorization_url,
    decode_state,
    encode_state,
    exchange_code_for_id_token,
    fetch_discovery_document,
    verify_id_token,
)
from app.auth.rbac import require_permission
from app.auth.security import create_access_token
from app.db.session import get_db_session
from app.models.oidc_provider_config import OidcProviderConfig
from app.models.organization import User
from app.schemas.auth import TokenResponse
from app.schemas.oidc import OidcProviderConfigCreate, OidcProviderConfigOut
from app.vault.credential_vault import encrypt_secret

router = APIRouter(tags=["oidc"])


@router.post("/oidc-provider-configs", response_model=OidcProviderConfigOut, status_code=201)
async def create_oidc_provider_config(
    payload: OidcProviderConfigCreate,
    user: User = Depends(require_permission("oidc_provider_config", "create")),
    session: AsyncSession = Depends(get_db_session),
) -> OidcProviderConfig:
    config = OidcProviderConfig(
        org_id=user.org_id,
        label=payload.label,
        issuer=payload.issuer,
        client_id=payload.client_id,
        encrypted_client_secret=encrypt_secret(payload.client_secret),
        redirect_uri=payload.redirect_uri,
        default_role=payload.default_role,
    )
    session.add(config)
    # Audit the creation event, never the client secret itself (§1.5).
    await write_audit_log(
        session,
        user=user,
        action="oidc_provider_config.create",
        resource_type="organization",
        resource_id=user.org_id,
        metadata={"label": payload.label, "issuer": payload.issuer},
    )
    await session.commit()
    await session.refresh(config)
    return config


@router.get("/oidc-provider-configs", response_model=list[OidcProviderConfigOut])
async def list_oidc_provider_configs(
    user: User = Depends(require_permission("oidc_provider_config", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> list[OidcProviderConfig]:
    result = await session.execute(
        select(OidcProviderConfig).where(OidcProviderConfig.org_id == user.org_id)
    )
    return list(result.scalars().all())


@router.delete("/oidc-provider-configs/{config_id}", status_code=204)
async def delete_oidc_provider_config(
    config_id: uuid.UUID,
    user: User = Depends(require_permission("oidc_provider_config", "delete")),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    config = await session.get(OidcProviderConfig, config_id)
    if config is None or config.org_id != user.org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "OIDC provider config not found")
    await write_audit_log(
        session,
        user=user,
        action="oidc_provider_config.delete",
        resource_type="organization",
        resource_id=user.org_id,
        metadata={"label": config.label},
    )
    await session.delete(config)
    await session.commit()


@router.get("/auth/oidc/{config_id}/login")
async def oidc_login(
    config_id: uuid.UUID, session: AsyncSession = Depends(get_db_session)
) -> RedirectResponse:
    """Unauthenticated by design — this is how a not-yet-logged-in user
    starts SSO. config_id must reference a registered OidcProviderConfig;
    which org they actually land in is decided by their verified
    identity at the callback, not by this step.
    """
    config = await session.get(OidcProviderConfig, config_id)
    if config is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "OIDC provider config not found")

    discovery = await fetch_discovery_document(config.issuer)
    state = encode_state(config.id)
    url = build_authorization_url(discovery, config, state)
    return RedirectResponse(url, status_code=status.HTTP_302_FOUND)


async def _find_or_provision_user(
    session: AsyncSession, config: OidcProviderConfig, identity: OidcIdentity
) -> User:
    result = await session.execute(
        select(User).where(User.oidc_subject == identity.subject, User.org_id == config.org_id)
    )
    user = result.scalar_one_or_none()
    if user is not None:
        return user

    if not identity.email:
        raise OidcError("IdP did not provide an email claim")

    # User.email is globally unique (not per-org) — an existing account
    # under a DIFFERENT org must never get silently linked to this login.
    result = await session.execute(select(User).where(User.email == identity.email))
    existing = result.scalar_one_or_none()
    if existing is not None:
        if existing.org_id != config.org_id:
            raise OidcError(
                f"{identity.email} is already registered under a different organization"
            )
        existing.oidc_subject = identity.subject
        await session.commit()
        return existing

    user = User(
        org_id=config.org_id,
        email=identity.email,
        hashed_password=None,
        role=config.default_role,
        oidc_subject=identity.subject,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


@router.get("/auth/oidc/callback", response_model=TokenResponse)
async def oidc_callback(
    code: str, state: str, session: AsyncSession = Depends(get_db_session)
) -> TokenResponse:
    """Returns our own JWT as JSON (same shape as POST /auth/login) rather
    than redirecting to a frontend page — there's no frontend in this
    build yet. A browser-based deployment would instead point
    redirect_uri at a frontend page that receives this and stores the
    token; documented simplification, not a protocol requirement.
    """
    try:
        config_id = decode_state(state)
    except OidcError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    config = await session.get(OidcProviderConfig, config_id)
    if config is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "OIDC provider config not found")

    try:
        discovery = await fetch_discovery_document(config.issuer)
        id_token = await exchange_code_for_id_token(discovery, config, code)
        identity = verify_id_token(id_token, discovery, config)
        user = await _find_or_provision_user(session, config, identity)
    except OidcError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc

    return TokenResponse(access_token=create_access_token(user.id))
