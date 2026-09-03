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

Deliberately narrow, matching an already-existing, already-documented
scope limit in app.agents.recon (DiscoveredParameter's docstring:
"HTML-only surface... JSON API bodies aren't covered"): this surfaces
endpoint URLs and GET query-string parameters, not JSON request-body
keys. Expanding that is real, separate follow-up work, not something to
fold in silently here.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.recon import DiscoveredParameter, _extract_query_params
from app.models.traffic import TrafficInteraction

# Same safe-by-default reasoning as ReconAgent.MAX_PAGES — a realistic
# browsing-session HAR won't come close to this, but an unbounded read
# of every TrafficInteraction ever imported for a long-lived Version
# shouldn't be allowed to blow up a scan's request volume unbounded.
MAX_SEEDED_ENDPOINTS = 300


async def seed_from_imported_traffic(
    session: AsyncSession, version_id: uuid.UUID
) -> tuple[list[str], list[DiscoveredParameter], list[str]]:
    result = await session.execute(
        select(TrafficInteraction.request_url)
        .where(
            TrafficInteraction.version_id == version_id,
            TrafficInteraction.source != "agent",
        )
        .distinct()
        .limit(MAX_SEEDED_ENDPOINTS)
    )
    all_urls = [row[0] for row in result.all()]

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

    return urls, parameters, websocket_urls
