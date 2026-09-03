"""Generic, configurable REST client for CMDB asset lookups (§9's
CMDBAdapter — "pulls asset inventory + owner/criticality"). Unlike Jira/
Slack (one real, documented API each), there's no single "the CMDB API" —
ServiceNow, Device42, and every in-house tool all expose different REST
shapes. Rather than guess one vendor's API blind and untestable, this is
a single client an org configures per-instance: a URL template with an
{identifier} placeholder (the same convention CredentialSet.
login_body_template already uses elsewhere in this codebase), an auth
header, and dot-path JSON field mappings for owner/criticality. Genuinely
fixture-testable against any realistic REST response shape.
"""

from dataclasses import dataclass
from typing import Any

import httpx


class CMDBLookupError(RuntimeError):
    pass


@dataclass
class AssetMetadata:
    identifier: str
    owner: str | None
    criticality: str | None
    raw: dict[str, Any]


def _read_json_path(data: Any, path: str) -> Any:
    """Walks a dot-separated path ("owner.email") through nested dicts.
    Missing/non-dict intermediate values resolve to None rather than
    raising — a CMDB response not having a field the org configured
    isn't a connection failure, just an absent value."""
    current = data
    for key in path.split("."):
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


class CMDBClient:
    def __init__(
        self,
        lookup_url_template: str,
        auth_header_name: str,
        auth_header_value: str,
        owner_json_path: str,
        criticality_json_path: str,
        *,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 15.0,
    ):
        self._lookup_url_template = lookup_url_template
        self._auth_header_name = auth_header_name
        self._auth_header_value = auth_header_value
        self._owner_json_path = owner_json_path
        self._criticality_json_path = criticality_json_path
        self._transport = transport
        self._timeout = timeout

    async def get_asset(self, identifier: str) -> AssetMetadata:
        url = self._lookup_url_template.format(identifier=identifier)
        headers = {self._auth_header_name: self._auth_header_value}
        try:
            async with httpx.AsyncClient(transport=self._transport, timeout=self._timeout) as client:
                response = await client.get(url, headers=headers)
        except httpx.RequestError as exc:
            raise CMDBLookupError(f"Could not reach CMDB at {url}: {exc}") from exc
        if response.status_code >= 400:
            raise CMDBLookupError(f"CMDB lookup for {identifier!r} failed: {response.status_code} {response.text}")
        try:
            data = response.json()
        except ValueError as exc:
            raise CMDBLookupError(f"CMDB response for {identifier!r} was not valid JSON") from exc

        return AssetMetadata(
            identifier=identifier,
            owner=_read_json_path(data, self._owner_json_path),
            criticality=_read_json_path(data, self._criticality_json_path),
            raw=data if isinstance(data, dict) else {"value": data},
        )
