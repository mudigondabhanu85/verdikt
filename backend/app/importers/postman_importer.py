import json
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlencode

from app.importers.base import TrafficImporter
from app.schemas.traffic import HttpInteraction, HttpRequest, HttpResponse


class PostmanImporter(TrafficImporter):
    """Normalizes a Postman Collection export (v2.0/v2.1 JSON) into the
    canonical HttpInteraction shape (§4) — one interaction per request
    item, recursing into folders. No real response: Postman's own saved
    example responses (if any) are ignored rather than guessed at, same
    convention as OpenApiImporter. Collection/folder/request-level auth
    blocks are intentionally NOT extracted here — an analyst attaches
    auth to the scan via a CredentialSet (credential_type="api_token"
    for a static bearer token/API key), not by trusting whatever a
    collection export happened to have saved.
    """

    def parse(self, file_path: str) -> list[HttpInteraction]:
        with open(file_path, encoding="utf-8") as f:
            collection = json.load(f)
        if not isinstance(collection, dict) or "info" not in collection or "item" not in collection:
            raise ValueError("not a Postman collection (missing top-level 'info'/'item')")

        now = datetime.now(timezone.utc)
        interactions: list[HttpInteraction] = []
        _walk_items(collection.get("item") or [], interactions, now)
        return interactions


def _walk_items(items: list, interactions: list[HttpInteraction], now: datetime) -> None:
    for item in items:
        if not isinstance(item, dict):
            continue
        if isinstance(item.get("item"), list):  # a folder — recurse
            _walk_items(item["item"], interactions, now)
            continue
        request = item.get("request")
        if not isinstance(request, dict):
            continue
        interaction = _interaction_from_request(request, now)
        if interaction is not None:
            interactions.append(interaction)


def _interaction_from_request(request: dict, now: datetime) -> HttpInteraction | None:
    method = str(request.get("method") or "GET").upper()
    url = _resolve_url(request.get("url"))
    if not url:
        return None
    headers = {
        h["key"]: str(h.get("value", ""))
        for h in (request.get("header") or [])
        if isinstance(h, dict) and h.get("key") and not h.get("disabled")
    }
    return HttpInteraction(
        request=HttpRequest(
            method=method, url=url, headers=headers, query_params={}, body=_resolve_body(request.get("body"))
        ),
        response=HttpResponse(status=None),
        source="postman_import",
        timestamp=now,
    )


def _resolve_url(url: Any) -> str | None:
    # Postman's "raw" already includes the query string — no separate
    # query_params extraction needed, unlike OpenApiImporter.
    if isinstance(url, str):
        return url
    if isinstance(url, dict):
        raw = url.get("raw")
        return str(raw) if raw else None
    return None


def _resolve_body(body: Any) -> str | None:
    if not isinstance(body, dict):
        return None
    mode = body.get("mode")
    if mode == "raw":
        raw = body.get("raw")
        return str(raw) if raw else None
    if mode == "urlencoded":
        params = body.get("urlencoded") or []
        pairs = {p["key"]: p.get("value", "") for p in params if isinstance(p, dict) and p.get("key")}
        return urlencode(pairs) if pairs else None
    return None
