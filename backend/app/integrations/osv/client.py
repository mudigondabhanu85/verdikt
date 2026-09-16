"""Client for OSV.dev's free, no-API-key vulnerability database
(https://osv.dev/docs/#tag/api), used by app.agents.vulnerable_components
to check a detected client-side JS library version for known CVEs. Same
shape as app.integrations.jira/burp's clients — a small, dependency-free
HTTP wrapper with a `transport=` escape hatch for tests, not a generic
SDK. This is the one integration client in this codebase that talks to a
fixed third-party service rather than an analyst-configured one — there
is nothing to store per-org, since OSV.dev's query endpoint needs no
credentials at all.
"""

import httpx

_QUERY_URL = "https://api.osv.dev/v1/query"


class OsvLookupError(RuntimeError):
    pass


class OsvClient:
    def __init__(self, *, transport: httpx.AsyncBaseTransport | None = None, timeout: float = 10.0):
        self._transport = transport
        self._timeout = timeout

    async def query_npm_package(self, *, name: str, version: str) -> list[dict]:
        """Returns the raw list of vuln objects OSV.dev reports for this
        exact (name, version) — empty list means "nothing known", not
        "definitely safe" (a library can always have an undisclosed or
        not-yet-published CVE). Never raises for "no results" — only for
        a genuine network/protocol failure, which callers should treat
        the same way every other best-effort external lookup in this
        codebase does (log and move on, never fail the scan over a
        third-party service being unreachable).
        """
        async with httpx.AsyncClient(transport=self._transport, timeout=self._timeout) as client:
            try:
                response = await client.post(
                    _QUERY_URL,
                    json={"version": version, "package": {"name": name, "ecosystem": "npm"}},
                )
            except httpx.HTTPError as exc:
                raise OsvLookupError(f"OSV.dev query failed for {name}@{version}: {exc}") from exc
        if response.status_code != 200:
            raise OsvLookupError(
                f"OSV.dev query for {name}@{version} returned HTTP {response.status_code}"
            )
        try:
            data = response.json()
        except ValueError as exc:
            raise OsvLookupError(f"OSV.dev returned non-JSON for {name}@{version}") from exc
        vulns = data.get("vulns", [])
        return vulns if isinstance(vulns, list) else []
