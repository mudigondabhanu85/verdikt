import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, UploadFile, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_version_or_404, write_audit_log
from app.auth.rbac import require_permission
from app.db.session import get_db_session
from app.importers.base import TrafficImporter
from app.importers.burp_file_importer import BurpFileImporter
from app.importers.har_importer import HarImporter
from app.importers.webinspect_importer import WebInspectMacroImporter
from app.importers.zest_importer import ZestImporter
from app.models.organization import User
from app.models.traffic import TrafficInteraction
from app.schemas.traffic import (
    HttpRequest,
    HttpResponse,
    ManualTrafficCreate,
    TrafficImportResult,
    TrafficInteractionOut,
)

router = APIRouter(prefix="/versions/{version_id}/traffic", tags=["traffic"])

# File-extension -> importer dispatch (§4). BurpFileImporter and
# WebInspectMacroImporter are real classes with a real interface, but no
# genuine sample export was obtainable to build their parsing logic
# against (see their module docstrings) — routed here like the working
# importers so the 501 they raise is a clean, documented API response,
# not a 500 crash or a silently missing endpoint.
_IMPORTERS: dict[str, type[TrafficImporter]] = {
    ".har": HarImporter,
    ".zst": ZestImporter,
    ".burp": BurpFileImporter,
    ".webmacro": WebInspectMacroImporter,
}


@router.post("/import", response_model=TrafficImportResult, status_code=201)
async def import_traffic(
    version_id: uuid.UUID,
    file: UploadFile,
    user: User = Depends(require_permission("traffic", "create")),
    session: AsyncSession = Depends(get_db_session),
) -> TrafficImportResult:
    await get_version_or_404(session, version_id, user.org_id)

    filename = file.filename or ""
    suffix = Path(filename.lower()).suffix
    importer_cls = _IMPORTERS.get(suffix)
    if importer_cls is None:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Unsupported traffic file type {suffix!r} — supported extensions: "
            f"{', '.join(sorted(_IMPORTERS))}",
        )

    contents = await file.read()
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(contents)
        tmp_path = tmp.name

    try:
        interactions = importer_cls().parse(tmp_path)
    except NotImplementedError as exc:
        raise HTTPException(status.HTTP_501_NOT_IMPLEMENTED, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, f"Could not parse {suffix} file: {exc}"
        ) from exc
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
        metadata={"source": suffix.lstrip("."), "filename": filename, "count": len(rows)},
    )
    await session.commit()
    for row in rows:
        await session.refresh(row)

    return TrafficImportResult(imported_count=len(rows), interaction_ids=[r.id for r in rows])


@router.post("/manual", response_model=TrafficInteractionOut, status_code=201)
async def add_manual_traffic(
    version_id: uuid.UUID,
    payload: ManualTrafficCreate,
    user: User = Depends(require_permission("traffic", "create")),
    session: AsyncSession = Depends(get_db_session),
) -> TrafficInteractionOut:
    """Accepts a single HTTP exchange directly — e.g. the Montoya Burp
    extension's "Send to Verdikt" context-menu action (§4) posts one
    request/response pair here instead of a whole file, which the HAR/
    Burp-file/Zest importers exist for.
    """
    await get_version_or_404(session, version_id, user.org_id)

    row = TrafficInteraction(
        version_id=version_id,
        credential_set_id=payload.credential_set_id,
        source="manual",
        timestamp=payload.timestamp or datetime.now(timezone.utc),
        request_method=payload.request.method,
        request_url=payload.request.url,
        request_headers=payload.request.headers,
        request_query_params=payload.request.query_params,
        request_body=payload.request.body,
        response_status=payload.response.status,
        response_headers=payload.response.headers,
        response_body=payload.response.body,
        timing_ms=payload.response.timing_ms,
    )
    session.add(row)
    await write_audit_log(
        session,
        user=user,
        action="traffic.manual_add",
        resource_type="version",
        resource_id=version_id,
        metadata={"url": payload.request.url},
    )
    await session.commit()
    await session.refresh(row)
    return _to_interaction_out(row)


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
