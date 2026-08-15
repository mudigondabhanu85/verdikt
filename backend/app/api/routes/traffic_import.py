import tempfile
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, UploadFile, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_version_or_404, write_audit_log
from app.auth.rbac import require_permission
from app.db.session import get_db_session
from app.importers.har_importer import HarImporter
from app.models.organization import User
from app.models.traffic import TrafficInteraction
from app.schemas.traffic import (
    HttpRequest,
    HttpResponse,
    TrafficImportResult,
    TrafficInteractionOut,
)

router = APIRouter(prefix="/versions/{version_id}/traffic", tags=["traffic"])


@router.post("/import", response_model=TrafficImportResult, status_code=201)
async def import_har(
    version_id: uuid.UUID,
    file: UploadFile,
    user: User = Depends(require_permission("traffic", "create")),
    session: AsyncSession = Depends(get_db_session),
) -> TrafficImportResult:
    await get_version_or_404(session, version_id, user.org_id)

    if not file.filename or not file.filename.lower().endswith(".har"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Only .har files are supported in Phase 0")

    contents = await file.read()
    with tempfile.NamedTemporaryFile(suffix=".har", delete=False) as tmp:
        tmp.write(contents)
        tmp_path = tmp.name

    try:
        interactions = HarImporter().parse(tmp_path)
    except Exception as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Could not parse HAR file: {exc}") from exc
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    rows = [
        TrafficInteraction(
            version_id=version_id,
            credential_set_id=interaction.credential_set_id,
            source=interaction.source,
            timestamp=interaction.timestamp,
            request_method=interaction.request.method,
            request_url=interaction.request.url,
            request_headers=interaction.request.headers,
            request_query_params=interaction.request.query_params,
            request_body=interaction.request.body,
            response_status=interaction.response.status,
            response_headers=interaction.response.headers,
            response_body=interaction.response.body,
            timing_ms=interaction.response.timing_ms,
        )
        for interaction in interactions
    ]
    session.add_all(rows)
    await write_audit_log(
        session,
        user=user,
        action="traffic.import",
        resource_type="version",
        resource_id=version_id,
        metadata={"source": "har", "filename": file.filename, "count": len(rows)},
    )
    await session.commit()
    for row in rows:
        await session.refresh(row)

    return TrafficImportResult(imported_count=len(rows), interaction_ids=[r.id for r in rows])


def _to_interaction_out(row: TrafficInteraction) -> TrafficInteractionOut:
    return TrafficInteractionOut(
        id=row.id,
        version_id=row.version_id,
        source=row.source,
        timestamp=row.timestamp,
        credential_set_id=row.credential_set_id,
        request=HttpRequest(
            method=row.request_method,
            url=row.request_url,
            headers=row.request_headers,
            query_params=row.request_query_params,
            body=row.request_body,
        ),
        response=HttpResponse(
            status=row.response_status,
            headers=row.response_headers,
            body=row.response_body,
            timing_ms=row.timing_ms,
        ),
    )


@router.get("", response_model=list[TrafficInteractionOut])
async def list_traffic_interactions(
    version_id: uuid.UUID,
    user: User = Depends(require_permission("traffic", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> list[TrafficInteractionOut]:
    await get_version_or_404(session, version_id, user.org_id)
    result = await session.execute(
        select(TrafficInteraction).where(TrafficInteraction.version_id == version_id)
    )
    return [_to_interaction_out(row) for row in result.scalars().all()]
