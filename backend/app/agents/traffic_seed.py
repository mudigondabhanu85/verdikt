"""§14 reference-app validation gap fix — imported traffic (HAR, Burp,
manual, Zest, macro-recorded) has been purely a passive record since §4
was built: nothing downstream of app.api.routes.traffic_import ever
read TrafficInteraction rows back out. That's fine for a traditional
server-rendered app (recon's own HTML crawl finds the same URLs), but
it means a client-rendered SPA — whose real API surface only shows up
in captured browser traffic, never in a GET / response's static HTML —
was untestable by Verdikt no matter how it was configured. This module
is the bridge: it surfaces already-imported traffic as additional
recon-equivalent output, merged into the same discovered_endpoints/
discovered_parameters every other agent already consumes.

Also the source for DiscoveredJsonBody (see app.agents.recon) — a
SPA's actual vulnerable surface (Juice Shop's product search, login,
basket, profile-update endpoints) is overwhelmingly a JSON request
body, never a query string or a server-rendered <form>, and captured
traffic is the only place a real one is ever observed.
"""

import json
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.recon import DiscoveredJsonBody, DiscoveredParameter, _extract_query_params
from app.models.traffic import TrafficInteraction

# Same safe-by-default reasoning as ReconAgent.MAX_PAGES — a realistic
# browsing-session HAR won't come close to this, but an unbounded read
# of every TrafficInteraction ever imported for a long-lived Version
# shouldn't be allowed to blow up a scan's request volume unbounded.
MAX_SEEDED_ENDPOINTS = 300


def _looks_like_json(content_type: str) -> bool:
    return "json" in content_type.lower()


def _extract_json_body(method: str, url: str, headers: dict, body: str | None) -> DiscoveredJsonBody | None:
    if method.upper() not in ("POST", "PUT", "PATCH") or not body:
        return None
    content_type = next((v for k, v in headers.items() if k.lower() == "content-type"), "")
    if not _looks_like_json(content_type):
        return None
    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return None
    # Only a flat, top-level object is testable this way — a bare list
    # or scalar body has no "field name" to attach a probe to, and a
    # nested object's own keys are left alone rather than guessing a
    # dot-path convention the target's own framework may not honor.
    if not isinstance(parsed, dict) or not parsed:
        return None
    return DiscoveredJsonBody(url=url, method=method.upper(), fields=list(parsed.keys()))


async def seed_from_imported_traffic(
    session: AsyncSession, version_id: uuid.UUID
) -> tuple[list[str], list[DiscoveredParameter], list[str], list[DiscoveredJsonBody]]:
    # Real, live-found bug: Postgres's `json` column type (unlike
    # `jsonb`) has no equality operator at all, so a SELECT DISTINCT
    # that includes request_headers — needed here to read a request's
    # Content-Type, on top of the request_url .distinct() already
    # relied on before this — fails outright with "could not identify
    # an equality operator for type json". Silently uncaught (this call
    # sits outside recon_node's own try/except — see graph.py), it left
    # both the AgentJob and the ScanRun permanently stuck at "running"
    # instead of failing loudly, discovered only by watching a real scan
    # never finish. Dedup URLs in Python instead of at the SQL level —
    # cheap at MAX_SEEDED_ENDPOINTS's bound, and sidesteps the type
    # entirely rather than casting request_headers to jsonb just to
    # satisfy DISTINCT.
    result = await session.execute(
        select(
            TrafficInteraction.request_url,
            TrafficInteraction.request_method,
            TrafficInteraction.request_headers,
            TrafficInteraction.request_body,
        )
        .where(
            TrafficInteraction.version_id == version_id,
            TrafficInteraction.source != "agent",
        )
        .limit(MAX_SEEDED_ENDPOINTS)
    )
    rows = result.all()
    all_urls = list(dict.fromkeys(row[0] for row in rows))

    # A real gap found via §14 live validation against OWASP Juice Shop:
    # its Angular SPA never has a literal ws:// string anywhere in fetched
    # HTML/JS text (socket.io's client builds the URL programmatically at
    # runtime), so app.agents.recon's own regex crawl can never discover
    # it — captured browser traffic (HAR/proxy) is the *only* source that
    # ever sees the real handshake URL. Same recon-equivalent treatment as
    # discovered_endpoints/discovered_parameters, just routed to
    # discovered_websocket_endpoints instead.
    urls = [u for u in all_urls if not u.startswith(("ws://", "wss://"))]
    websocket_urls = [u for u in all_urls if u.startswith(("ws://", "wss://"))]

    parameters: list[DiscoveredParameter] = []
    for url in urls:
        parameters.extend(_extract_query_params(url))

    json_bodies: list[DiscoveredJsonBody] = []
    for url, method, headers, body in rows:
        parsed_body = _extract_json_body(method, url, headers or {}, body)
        if parsed_body is not None:
            json_bodies.append(parsed_body)

    return urls, parameters, websocket_urls, json_bodies
