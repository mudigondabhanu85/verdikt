import json
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
from app.importers.openapi_importer import OpenApiImporter
from app.importers.postman_importer import PostmanImporter
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


def _strip_nul_bytes(value: str | None) -> str | None:
    """A real bug found via §14 live validation against OWASP Juice
    Shop: a captured HAR entry for a binary asset (e.g. a PNG) decodes
    to text containing literal NUL (0x00) bytes — valid Python str
    content, but Postgres text/varchar columns reject NUL outright
    ("PostgreSQL text fields cannot contain NUL (0x00) bytes"), which
    took down the *entire* batch insert, not just that one row. Stripped
    rather than truncated/rejected — response_body/request_body exist
    here for human/agent inspection context, not exact binary
    reconstruction, so a NUL-free approximation is the right tradeoff
    over failing the whole import.
    """
    if value is None:
        return None
    return value.replace("\x00", "")

# File-extension -> importer dispatch (§4). BurpFileImporter and
# WebInspectMacroImporter are real classes with a real interface, but no
# genuine sample export was obtainable to build their parsing logic
# against (see their module docstrings) — routed here like the working
# importers so the 501 they raise is a clean, documented API response,
# not a 500 crash or a silently missing endpoint.
#
# ".json" is deliberately absent from this dict — HAR, Postman
# collections, and OpenAPI-as-JSON all commonly use a plain ".json"
# extension, so which importer a ".json" upload needs can't be decided
# by extension alone. See _resolve_json_importer, which sniffs the
# actual parsed content instead. ".yaml"/".yml" are unambiguous (only
# OpenAPI uses them here) so those go straight in the dict.
_IMPORTERS: dict[str, type[TrafficImporter]] = {
    ".har": HarImporter,
    ".yaml": OpenApiImporter,
    ".yml": OpenApiImporter,
    ".zst": ZestImporter,
    ".burp": BurpFileImporter,
    ".webmacro": WebInspectMacroImporter,
}


def _resolve_json_importer(contents: bytes) -> type[TrafficImporter]:
    """A ".json" upload could be a HAR export, a Postman collection, or
    an OpenAPI document saved with a .json extension instead of .yaml —
    sniff the parsed shape rather than guessing from the extension.
    Anything that doesn't match a known shape (including malformed
    JSON) falls back to HarImporter, preserving this route's pre-import
    behavior for actual HAR-as-.json files — HarImporter's own
    parse() raises a clean, already-handled error for genuinely
    unparseable content either way.
    """
    try:
        parsed = json.loads(contents)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return HarImporter
    if isinstance(parsed, dict):
        if "openapi" in parsed or "swagger" in parsed:
            return OpenApiImporter
        if "info" in parsed and "item" in parsed:
            return PostmanImporter
    return HarImporter

# A full Burp/HAR export of a large crawl can comfortably exceed 1GB —
# there was previously no ceiling at all here, which meant an oversized
# file was read into memory in one `await file.read()` call with no
# feedback until either the process ran out of memory (silent connection
# drop — see app.main's global exception handler for why that then
# showed up in the browser as a misleading CORS error rather than any
# real message) or it just hung. Read in chunks up to this cap instead,
# so an oversized file gets a clean, immediate 413 rather than either
# outcome. 2GB gives real headroom above the largest real export seen so
# far (a 1.15GB .burp file).
MAX_TRAFFIC_IMPORT_BYTES = 2 * 1024 * 1024 * 1024
_READ_CHUNK_SIZE = 8 * 1024 * 1024


async def _read_upload_capped(file: UploadFile, *, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(_READ_CHUNK_SIZE)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise HTTPException(
                status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                f"Traffic file exceeds the {max_bytes // (1024 * 1024)}MB import limit",
            )
        chunks.append(chunk)
    return b"".join(chunks)


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

    if suffix and suffix != ".json" and suffix not in _IMPORTERS:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Unsupported traffic file type {suffix!r} — supported extensions: "
            f"{', '.join(sorted({*_IMPORTERS, '.json'}))}",
        )

    contents = await _read_upload_capped(file, max_bytes=MAX_TRAFFIC_IMPORT_BYTES)

    if suffix == ".json":
        importer_cls = _resolve_json_importer(contents)
    elif not suffix:
        # Burp's own "Save selected items" export has no extension at
        # all by default (unlike a HAR/Zest export, which always gets
        # one) — an extensionless upload is routed to BurpFileImporter
        # rather than rejected outright as "unsupported file type ''".
        importer_cls = _IMPORTERS[".burp"]
    else:
        importer_cls = _IMPORTERS[suffix]

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
            request_body=_strip_nul_bytes(interaction.request.body),
            response_status=interaction.response.status,
            response_headers=interaction.response.headers,
            response_body=_strip_nul_bytes(interaction.response.body),
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
        request_body=_strip_nul_bytes(payload.request.body),
        response_status=payload.response.status,
        response_headers=payload.response.headers,
        response_body=_strip_nul_bytes(payload.response.body),
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


@router.delete("/{interaction_id}", status_code=204)
async def delete_traffic_interaction(
    version_id: uuid.UUID,
    interaction_id: uuid.UUID,
    user: User = Depends(require_permission("traffic", "delete")),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    """Surgical removal of one bad/sensitive captured request — e.g. an
    analyst notices one row in a HAR import carries a live production
    secret they don't want sitting in Verdikt's DB, without needing to
    delete and re-import the entire batch to drop just that one row.
    """
    await get_version_or_404(session, version_id, user.org_id)
    row = await session.get(TrafficInteraction, interaction_id)
    if row is None or row.version_id != version_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Traffic interaction not found")
    await write_audit_log(
        session,
        user=user,
        action="traffic.delete",
        resource_type="version",
        resource_id=version_id,
        metadata={"interaction_id": str(interaction_id), "source": row.source, "url": row.request_url},
    )
    await session.delete(row)
    await session.commit()


@router.delete("", status_code=204)
async def clear_traffic_interactions(
    version_id: uuid.UUID,
    source: str | None = None,
    user: User = Depends(require_permission("traffic", "delete")),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    """Bulk removal — the common case for "delete what I uploaded":
    there's no import-batch id (each imported exchange is its own row,
    see TrafficInteraction), so `source` lets an analyst clear just one
    import type (e.g. `?source=har` after a bad HAR capture) without
    touching manually-added entries or other imports, while omitting it
    clears everything for this version — a full reset before
    re-uploading.
    """
    await get_version_or_404(session, version_id, user.org_id)
    query = select(TrafficInteraction).where(TrafficInteraction.version_id == version_id)
    if source is not None:
        query = query.where(TrafficInteraction.source == source)
    rows = (await session.execute(query)).scalars().all()
    await write_audit_log(
        session,
        user=user,
        action="traffic.clear",
        resource_type="version",
        resource_id=version_id,
        metadata={"source": source, "count": len(rows)},
    )
    for row in rows:
        await session.delete(row)
    await session.commit()
