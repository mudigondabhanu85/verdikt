"""Checkmarx's `.zst` traffic export is Zstandard-compressed OWASP ZAP
"Zest" script JSON (§4) — a real, open, documented format
(https://github.com/zaproxy/zest, and Checkmarx's own Business Flow
Recorder / Sequences CLI docs), not a proprietary Checkmarx format. This
importer decompresses the file and maps every ZestRequest statement to
our canonical HttpInteraction; ZestSetVariable/ZestAssertion/etc.
statements aren't HTTP exchanges and are skipped.
"""

import json
from datetime import datetime, timezone

import zstandard

from app.importers.base import TrafficImporter
from app.schemas.traffic import HttpInteraction, HttpRequest, HttpResponse


def _parse_raw_headers(raw: str | None) -> dict[str, str]:
    """Zest stores headers as a raw HTTP header block (including the
    request/status line) — this pulls out just the "Name: value" lines.
    """
    if not raw:
        return {}
    headers: dict[str, str] = {}
    for line in raw.replace("\r\n", "\n").split("\n"):
        line = line.strip()
        if not line or ":" not in line:
            continue  # skips the request/status line and blank separators
        name, _, value = line.partition(":")
        headers[name.strip()] = value.strip()
    return headers


class ZestImporter(TrafficImporter):
    """Parses a Zstandard-compressed Zest script (.zst) into HttpInteractions."""

    def parse(self, file_path: str) -> list[HttpInteraction]:
        with open(file_path, "rb") as f:
            compressed = f.read()

        try:
            raw_json = zstandard.ZstdDecompressor().decompress(compressed)
        except zstandard.ZstdError as exc:
            raise ValueError(f"Not a valid Zstandard-compressed file: {exc}") from exc

        try:
            script = json.loads(raw_json)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Decompressed content is not valid Zest JSON: {exc}") from exc

        interactions: list[HttpInteraction] = []
        for statement in script.get("statements", []):
            if statement.get("elementType") != "ZestRequest":
                continue
            interactions.append(self._to_interaction(statement))
        return interactions

    def _to_interaction(self, statement: dict) -> HttpInteraction:
        response = statement.get("response") or {}
        request = HttpRequest(
            method=statement.get("method", "GET"),
            url=statement.get("url", ""),
            headers=_parse_raw_headers(statement.get("headers")),
            body=statement.get("data") or None,
        )
        http_response = HttpResponse(
            status=response.get("statusCode"),
            headers=_parse_raw_headers(response.get("headers")) or None,
            body=response.get("body"),
            timing_ms=response.get("responseTimeInMs"),
        )
        return HttpInteraction(
            request=request,
            response=http_response,
            source="zst_traffic",
            timestamp=datetime.now(timezone.utc),
        )
