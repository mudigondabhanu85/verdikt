"""Shared "what substring proves this finding" matching logic, used by
every report format (HTML/DOCX/PDF) and mirrored in the frontend's
FindingsTab.tsx (keep both in sync).

Real, live-found gap: Evidence.payload is the exploit string that was
*sent* (e.g. command-injection's "; echo VERDIKT7228dae9"), but what
actually proves the finding in the *response* is often only part of it
(the bare "VERDIKT7228dae9" marker — a shell echoes its output, not the
command that produced it) — a literal full-payload match finds nothing
in either direction for that class of check, silently leaving both
panes unhighlighted despite the finding being completely real. A second,
structural gap: the request itself is very often form/query-encoded
(DVWA's command-injection field arrives as "%3B+echo+VERDIKT..."), so
even a check whose payload genuinely is what proves it (SQL injection's
bare "'") only ever highlighted in the response, never the request.
"""

import re
from urllib.parse import quote_plus

# Every marker-based check in this codebase already embeds one of these
# recognizable tokens inside its full payload.
MARKER_RE = re.compile(r"VERDIKT[0-9a-f]{6,}|verdikt_[A-Za-z0-9]{6,}|verdikt[0-9]{4,}")


def highlight_candidates(payload: str) -> list[str]:
    """Every literal substring worth trying to highlight, derived from
    `payload`, in priority order: the literal payload itself, its
    application/x-www-form-urlencoded encoding, and any embedded
    VERDIKT/verdikt marker token. Callers should highlight every
    occurrence of the *first* candidate that actually appears in the
    text being rendered.
    """
    candidates = [payload]
    encoded = quote_plus(payload)
    if encoded not in candidates:
        candidates.append(encoded)
    marker_match = MARKER_RE.search(payload)
    if marker_match and marker_match.group(0) not in candidates:
        candidates.append(marker_match.group(0))
    return candidates


def find_highlight_match(text: str, payload: str | None) -> str | None:
    """Returns the first highlight candidate that literally appears in
    `text` (both taken as already in whatever encoding they're compared
    in — callers that need escaping do it themselves), or None if
    `payload` is falsy or no candidate matches."""
    if not payload:
        return None
    for candidate in highlight_candidates(payload):
        if candidate and candidate in text:
            return candidate
    return None
