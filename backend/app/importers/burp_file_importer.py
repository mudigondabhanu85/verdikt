import base64
from datetime import datetime, timezone
from xml.etree import ElementTree

from app.importers.base import TrafficImporter
from app.schemas.traffic import HttpInteraction, HttpRequest, HttpResponse

_BINARY_PROJECT_ERROR = (
    "This looks like Burp's proprietary full-project save (Project > Save/Save as, "
    "or a .burp project opened at startup) — that binary format is undocumented "
    "(no public spec exists) and remains unsupported; guessing at its structure "
    "risks silently mis-parsing real traffic rather than failing cleanly. Instead, "
    "in Burp: Proxy > HTTP history (or Target > Site map), select the items you "
    "want, right-click -> \"Save selected items\", and import that XML export "
    "instead — this importer parses that format for real."
)


class BurpFileImporter(TrafficImporter):
    """Parses Burp's "Save selected items"/"Save all items" XML export
    (Proxy > HTTP history or Target > Site map, right-click -> Save
    items) — an <items> document with one <item> per HTTP interaction,
    each holding base64-encoded raw request/response messages, per
    Burp's own embedded DTD. This is a DIFFERENT thing from Burp's
    proprietary full-project ".burp" binary save (Project > Save/Save
    as) — that format is undocumented and stays unsupported (see
    _BINARY_PROJECT_ERROR). The two are told apart by the first bytes:
    this XML export always starts with an XML declaration; the binary
    project format never does.
    """

    def parse(self, file_path: str) -> list[HttpInteraction]:
        with open(file_path, "rb") as f:
            head = f.read(16).lstrip()
        if not head.startswith(b"<?xml"):
            raise NotImplementedError(_BINARY_PROJECT_ERROR)

        root = ElementTree.parse(file_path).getroot()
        if root.tag != "items":
            raise ValueError("not a Burp 'Save items' XML export (no top-level <items>)")

        interactions: list[HttpInteraction] = []
        for item in root.findall("item"):
            interaction = _parse_item(item)
            if interaction is not None:
                interactions.append(interaction)
        return interactions


def _parse_item(item: ElementTree.Element) -> HttpInteraction | None:
    url_el = item.find("url")
    if url_el is None or not url_el.text:
        return None

    method = item.findtext("method") or "GET"
    timestamp = _parse_burp_time(item.findtext("time") or "")
    request_headers, request_body = _decode_raw_message(item.find("request"))
    response_headers, response_body = _decode_raw_message(item.find("response"))

    status_text = item.findtext("status")
    status = int(status_text) if status_text and status_text.strip().isdigit() else None

    return HttpInteraction(
        request=HttpRequest(
            method=method,
            url=url_el.text,
            headers=request_headers,
            # Burp's <url> already includes the query string for GETs
            # (same convention PostmanImporter follows for url.raw) —
            # no separate structured query_params extraction needed.
            query_params={},
            body=request_body,
        ),
        response=HttpResponse(status=status, headers=response_headers, body=response_body),
        source="burp_file",
        timestamp=timestamp,
    )


def _decode_raw_message(el: ElementTree.Element | None) -> tuple[dict[str, str], str | None]:
    if el is None or not el.text:
        return {}, None
    try:
        raw_bytes = base64.b64decode(el.text) if el.get("base64") == "true" else el.text.encode()
    except (ValueError, UnicodeEncodeError):
        return {}, None
    raw = raw_bytes.decode("utf-8", errors="replace")

    separator = "\r\n\r\n" if "\r\n\r\n" in raw else "\n\n"
    head, _, body = raw.partition(separator)
    lines = head.split("\r\n") if "\r\n" in head else head.split("\n")

    headers: dict[str, str] = {}
    for line in lines[1:]:  # lines[0] is the request/status line, not a header
        name, sep, value = line.partition(":")
        if sep:
            headers[name.strip()] = value.strip()
    return headers, (body or None)


def _parse_burp_time(text: str) -> datetime:
    """Java's Date.toString() format, e.g. "Tue Mar 31 16:23:42 EDT 2026".
    Best-effort only (timestamps here are for audit/ordering context, not
    anything security-critical) — %Z's timezone-abbreviation recognition
    is platform-dependent (many US zone abbreviations aren't recognized
    on some platforms/locales), so a parse failure falls back to
    treating it as UTC, and total failure falls back to "now" — same
    tolerant-fallback style as HarImporter's _parse_timestamp.
    """
    if not text:
        return datetime.now(timezone.utc)
    for fmt in ("%a %b %d %H:%M:%S %Z %Y", "%a %b %d %H:%M:%S %Y"):
        source = text
        if fmt == "%a %b %d %H:%M:%S %Y":
            parts = text.split()
            if len(parts) != 6:
                continue
            source = " ".join(parts[:4] + parts[5:])  # drop the tz abbreviation token
        try:
            parsed = datetime.strptime(source, fmt)
        except ValueError:
            continue
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc)
