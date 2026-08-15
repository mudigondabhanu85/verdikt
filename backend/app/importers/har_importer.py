import base64
import json
from datetime import datetime, timezone

from app.importers.base import TrafficImporter
from app.schemas.traffic import HttpInteraction, HttpRequest, HttpResponse


def _headers_to_dict(headers: list[dict] | None) -> dict[str, str]:
    if not headers:
        return {}
    return {h["name"]: h["value"] for h in headers if "name" in h}


def _query_to_dict(query_string: list[dict] | None) -> dict[str, str]:
    if not query_string:
        return {}
    return {q["name"]: q["value"] for q in query_string if "name" in q}


def _decode_content(content: dict | None) -> str | None:
    if not content or "text" not in content:
        return None
    text = content["text"]
    if content.get("encoding") == "base64":
        try:
            return base64.b64decode(text).decode("utf-8", errors="replace")
        except Exception:
            return text
    return text


def _parse_timestamp(started_date_time: str | None) -> datetime:
    if not started_date_time:
        return datetime.now(timezone.utc)
    # HAR timestamps are ISO 8601, e.g. "2026-08-14T12:00:00.000Z"
    normalized = started_date_time.replace("Z", "+00:00")
    return datetime.fromisoformat(normalized)


class HarImporter(TrafficImporter):
    """Parses the public HAR 1.2 spec (log.entries[]). Handles missing
    optional fields defensively since real-world HAR exports vary widely
    (no postData on GETs, no response content on errors, base64-encoded
    binary bodies, etc.).
    """

    def parse(self, file_path: str) -> list[HttpInteraction]:
        with open(file_path, encoding="utf-8") as f:
            har = json.load(f)

        entries = har.get("log", {}).get("entries", [])
        interactions: list[HttpInteraction] = []

        for entry in entries:
            req = entry.get("request", {})
            res = entry.get("response", {})

            http_request = HttpRequest(
                method=req.get("method", "GET"),
                url=req.get("url", ""),
                headers=_headers_to_dict(req.get("headers")),
                query_params=_query_to_dict(req.get("queryString")),
                body=(req.get("postData") or {}).get("text"),
            )
            http_response = HttpResponse(
                status=res.get("status"),
                headers=_headers_to_dict(res.get("headers")) or None,
                body=_decode_content(res.get("content")),
                timing_ms=entry.get("time"),
            )
            interactions.append(
                HttpInteraction(
                    request=http_request,
                    response=http_response,
                    source="har",
                    timestamp=_parse_timestamp(entry.get("startedDateTime")),
                )
            )

        return interactions
