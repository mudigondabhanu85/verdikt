"""§7 frontend — serves object-storage content (currently just Finding
evidence screenshots, e.g. app.agents.clickjacking_proof/stored_xss's
PNG captures) back over HTTP so the browser can render an <img src=...>
for it. Object keys are UUID-namespaced (unguessable in practice), but
this does NOT verify a key belongs to a scan run within the caller's
own org — a known simplification for this pass, not a claim of full
per-org isolation on this specific route. Tightening it would mean
parsing the (evidence-producer-specific) key convention to recover a
scan_run_id and checking it against the caller's org, which isn't a
uniform format across every agent that writes evidence yet.
"""

from fastapi import APIRouter, Depends, HTTPException, Response, status

from app.auth.rbac import require_permission
from app.models.organization import User
from app.storage.local_disk import get_object_storage

router = APIRouter(tags=["objects"])


@router.get("/objects/{key:path}")
async def get_object(
    key: str,
    user: User = Depends(require_permission("scan", "read")),
) -> Response:
    try:
        data = await get_object_storage().get(key)
    except (FileNotFoundError, ValueError) as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Object not found") from exc

    content_type = "image/png" if key.endswith(".png") else "application/octet-stream"
    return Response(content=data, media_type=content_type)
