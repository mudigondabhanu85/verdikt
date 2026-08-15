"""Shared numeric-ID substitution helpers for horizontal-IDOR-style
detection. Used by app.agents.access_control (auto-discovered endpoints)
and app.agents.business_logic (analyst-specified endpoints via the
resource_isolation rule type) — same mechanism, different endpoint
source.
"""

import re
from urllib.parse import urlsplit, urlunsplit

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
