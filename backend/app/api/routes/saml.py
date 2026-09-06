"""SAML SP metadata + Okta IdP config endpoints (§9). Configured once per
organization (not per project), mirroring how OIDC config works in
app.api.routes.oidc. Only the metadata-exchange half of the SAML setup
flow is implemented here — actually consuming a SAML assertion at
`/saml/acs/{config_id}` (i.e. the real Okta-side login redirect landing
back at Verdikt) is NOT implemented in this pass: python3-saml's
assertion-validation path needs a real Okta tenant's IdP metadata to
meaningfully test against, which isn't available in this environment.
What IS implemented and real: generating a genuinely valid SP metadata
XML document (via the real python3-saml library) for the org's Okta
admin to consume, and storing whatever IdP metadata they hand back.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import write_audit_log
from app.auth.rbac import require_permission
from app.auth.saml import generate_sp_metadata
from app.db.session import get_db_session
from app.models.organization import User
from app.models.saml_config import SamlConfig
from app.schemas.saml_config import SamlConfigCreate, SamlConfigOut, SamlIdpMetadataUpload

router = APIRouter(prefix="/saml-configs", tags=["saml-configs"])


def _to_out(config: SamlConfig) -> SamlConfigOut:
    return SamlConfigOut(
        id=config.id,
        org_id=config.org_id,
        label=config.label,
        idp_sso_url=config.idp_sso_url,
        idp_entity_id=config.idp_entity_id,
        has_idp_metadata=bool(
            config.idp_metadata_xml or (config.idp_sso_url and config.idp_x509_cert)
        ),
    )


@router.post("", response_model=SamlConfigOut, status_code=201)
async def create_saml_config(
    payload: SamlConfigCreate,
    user: User = Depends(require_permission("saml_config", "create")),
    session: AsyncSession = Depends(get_db_session),
) -> SamlConfigOut:
    config = SamlConfig(org_id=user.org_id, label=payload.label)
    session.add(config)
    await write_audit_log(
        session,
        user=user,
        action="saml_config.create",
        resource_type="organization",
        resource_id=user.org_id,
        metadata={"label": payload.label},
    )
    await session.commit()
    await session.refresh(config)
    return _to_out(config)


@router.get("", response_model=list[SamlConfigOut])
async def list_saml_configs(
    user: User = Depends(require_permission("saml_config", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> list[SamlConfigOut]:
    result = await session.execute(select(SamlConfig).where(SamlConfig.org_id == user.org_id))
    return [_to_out(c) for c in result.scalars().all()]


@router.delete("/{config_id}", status_code=204)
async def delete_saml_config(
    config_id: uuid.UUID,
    user: User = Depends(require_permission("saml_config", "delete")),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    config = await session.get(SamlConfig, config_id)
    if config is None or config.org_id != user.org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "SAML config not found")
    await write_audit_log(
        session,
        user=user,
        action="saml_config.delete",
        resource_type="organization",
        resource_id=user.org_id,
        metadata={"label": config.label},
    )
    await session.delete(config)
    await session.commit()


@router.get("/{config_id}/metadata.xml")
async def download_sp_metadata(
    config_id: uuid.UUID,
    request: Request,
    user: User = Depends(require_permission("saml_config", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> Response:
    """Downloads this Verdikt organization's SP metadata XML — the file
    to hand to the org's Okta admin when creating the Okta SAML app
    integration (§9 step 1)."""
    config = await session.get(SamlConfig, config_id)
    if config is None or config.org_id != user.org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "SAML config not found")

    base = str(request.base_url).rstrip("/")
    entity_id = f"{base}/saml-configs/{config_id}/metadata.xml"
    acs_url = f"{base}/saml/acs/{config_id}"
    xml = generate_sp_metadata(entity_id, acs_url)
    return Response(content=xml, media_type="application/xml")


@router.post("/{config_id}/idp-metadata", response_model=SamlConfigOut)
async def upload_idp_metadata(
    config_id: uuid.UUID,
    payload: SamlIdpMetadataUpload,
    user: User = Depends(require_permission("saml_config", "update")),
    session: AsyncSession = Depends(get_db_session),
) -> SamlConfigOut:
    """Accepts either Okta's full IdP metadata XML, or the three
    individual fields Okta sometimes hands out separately, to complete
    the trust relationship (§9 step 2)."""
    config = await session.get(SamlConfig, config_id)
    if config is None or config.org_id != user.org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "SAML config not found")

    has_xml = bool(payload.idp_metadata_xml)
    has_fields = bool(payload.idp_sso_url and payload.idp_entity_id and payload.idp_x509_cert)
    if not has_xml and not has_fields:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Provide either idp_metadata_xml, or idp_sso_url + idp_entity_id + idp_x509_cert together",
        )

    config.idp_metadata_xml = payload.idp_metadata_xml
    config.idp_sso_url = payload.idp_sso_url
    config.idp_entity_id = payload.idp_entity_id
    config.idp_x509_cert = payload.idp_x509_cert

    await write_audit_log(
        session,
        user=user,
        action="saml_config.upload_idp_metadata",
        resource_type="organization",
        resource_id=user.org_id,
        metadata={"label": config.label, "via_xml": has_xml},
    )
    await session.commit()
    await session.refresh(config)
    return _to_out(config)
