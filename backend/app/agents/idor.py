"""Shared ID-substitution helpers for horizontal-IDOR-style detection.
Used by app.agents.access_control (auto-discovered endpoints) and
app.agents.business_logic (analyst-specified endpoints via the
resource_isolation rule type) — same mechanism, different endpoint
source.
"""

import re
import secrets
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

_NUMERIC_ID_RE = re.compile(r"^\d+$")


def find_numeric_id_segment(url: str) -> tuple[int, str] | None:
    segments = urlsplit(url).path.split("/")
    for index in range(len(segments) - 1, -1, -1):
        if _NUMERIC_ID_RE.match(segments[index]):
            return index, segments[index]
    return None


def substitute_path_segment(url: str, index: int, new_value: str) -> str:
    parsed = urlsplit(url)
    segments = parsed.path.split("/")
    segments[index] = new_value
    return urlunsplit((parsed.scheme, parsed.netloc, "/".join(segments), parsed.query, ""))


def nearby_ids(value: str) -> list[str]:
    n = int(value)
    return [str(candidate) for candidate in (n - 1, n + 1) if candidate >= 0 and str(candidate) != value]


def find_query_identifier(url: str) -> tuple[str, str] | None:
    """The query-string counterpart to find_numeric_id_segment — a real,
    at-least-as-common IDOR shape found live: a lookup endpoint keyed by
    a query parameter (e.g. "?email=", "?user_id=") rather than a
    REST-style "/resource/{id}" numeric path segment. Returns the first
    non-empty query parameter, since the URL under test here always
    comes from a specific rule/endpoint an analyst or the AI planner
    already flagged as worth checking, not an arbitrary crawled page.
    """
    query = urlsplit(url).query
    if not query:
        return None
    parsed = parse_qs(query, keep_blank_values=True)
    for name, values in parsed.items():
        if values and values[0]:
            return name, values[0]
    return None


def substitute_query_param(url: str, name: str, new_value: str) -> str:
    parsed = urlsplit(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[name] = [new_value]
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(params, doseq=True), ""))


def sibling_values(value: str) -> list[str]:
    """Generalizes nearby_ids to non-numeric identifiers (email
    addresses, usernames, opaque tokens/UUIDs) found via
    find_query_identifier — "nearby" has no meaning for a string, so
    this generates a fresh, unambiguously different value of roughly
    the same shape instead, to prove the endpoint isn't scoped to the
    one identifier value an analyst/AI happened to observe.
    """
    if _NUMERIC_ID_RE.match(value):
        return nearby_ids(value)
    token = secrets.token_hex(4)
    if "@" in value:
        _, _, domain = value.partition("@")
        return [f"verdikt-idor-probe-{token}@{domain or 'example.test'}"]
    return [f"verdikt-idor-probe-{token}"]
