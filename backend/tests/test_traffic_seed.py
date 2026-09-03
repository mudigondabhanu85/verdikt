import uuid
from datetime import datetime, timezone

from app.agents.traffic_seed import MAX_SEEDED_ENDPOINTS, seed_from_imported_traffic
from app.models.traffic import TrafficInteraction
from tests.conftest import session_scope


async def _add_interaction(session, version_id, url: str, *, source: str = "har") -> None:
    session.add(
        TrafficInteraction(
            version_id=version_id,
            source=source,
            timestamp=datetime.now(timezone.utc),
            request_method="GET",
            request_url=url,
            request_headers={},
            request_query_params={},
        )
    )


async def test_seeds_urls_and_query_params_from_imported_traffic(db_adapter):
    version_id = uuid.uuid4()
    async with session_scope(db_adapter) as session:
        await _add_interaction(session, version_id, "https://spa.test/rest/products")
        await _add_interaction(session, version_id, "https://spa.test/rest/user/whoami?lang=en")
        await session.commit()

        urls, params, ws_urls = await seed_from_imported_traffic(session, version_id)

    assert set(urls) == {"https://spa.test/rest/products", "https://spa.test/rest/user/whoami?lang=en"}
    assert len(params) == 1
    assert params[0].name == "lang"
    assert params[0].sample_value == "en"
    assert params[0].url == "https://spa.test/rest/user/whoami?lang=en"
    assert ws_urls == []


async def test_excludes_agent_sourced_traffic(db_adapter):
    """Agent-issued requests are recorded to TrafficInteraction too (the
    §1.3 audit trail, app.agents.http_client._record_traffic) — feeding
    those back into discovery would be a feedback loop, not real new
    surface from an external import."""
    version_id = uuid.uuid4()
    async with session_scope(db_adapter) as session:
        await _add_interaction(session, version_id, "https://spa.test/rest/imported", source="har")
        await _add_interaction(session, version_id, "https://spa.test/rest/agent-issued", source="agent")
        await session.commit()

        urls, _params, _ws_urls = await seed_from_imported_traffic(session, version_id)

    assert urls == ["https://spa.test/rest/imported"]


async def test_excludes_other_versions_traffic(db_adapter):
    version_a = uuid.uuid4()
    version_b = uuid.uuid4()
    async with session_scope(db_adapter) as session:
        await _add_interaction(session, version_a, "https://a.test/x")
        await _add_interaction(session, version_b, "https://b.test/y")
        await session.commit()

        urls, _params, _ws_urls = await seed_from_imported_traffic(session, version_a)

    assert urls == ["https://a.test/x"]


async def test_dedupes_repeated_urls(db_adapter):
    version_id = uuid.uuid4()
    async with session_scope(db_adapter) as session:
        await _add_interaction(session, version_id, "https://spa.test/rest/products")
        await _add_interaction(session, version_id, "https://spa.test/rest/products")
        await session.commit()

        urls, _params, _ws_urls = await seed_from_imported_traffic(session, version_id)

    assert urls == ["https://spa.test/rest/products"]


async def test_respects_max_seeded_endpoints_bound(db_adapter):
    version_id = uuid.uuid4()
    async with session_scope(db_adapter) as session:
        for i in range(MAX_SEEDED_ENDPOINTS + 20):
            await _add_interaction(session, version_id, f"https://spa.test/rest/item/{i}")
        await session.commit()

        urls, _params, _ws_urls = await seed_from_imported_traffic(session, version_id)

    assert len(urls) == MAX_SEEDED_ENDPOINTS


async def test_no_imported_traffic_returns_empty(db_adapter):
    async with session_scope(db_adapter) as session:
        urls, params, ws_urls = await seed_from_imported_traffic(session, uuid.uuid4())

    assert urls == []
    assert params == []
    assert ws_urls == []


async def test_extracts_websocket_urls_separately_from_http_urls(db_adapter):
    """A real gap found via §14 live validation against OWASP Juice Shop:
    its socket.io handshake URL only ever appears in captured browser
    traffic (an Angular SPA client builds it programmatically at
    runtime), never as a literal string in fetched HTML/JS — so
    app.agents.recon's own crawl can never discover it. Imported traffic
    is the only source that can seed discovered_websocket_endpoints for
    a target like this."""
    version_id = uuid.uuid4()
    async with session_scope(db_adapter) as session:
        await _add_interaction(session, version_id, "https://spa.test/rest/products")
        await _add_interaction(
            session, version_id, "ws://spa.test/socket.io/?EIO=4&transport=websocket&sid=abc123"
        )
        await session.commit()

        urls, _params, ws_urls = await seed_from_imported_traffic(session, version_id)

    assert urls == ["https://spa.test/rest/products"]
    assert ws_urls == ["ws://spa.test/socket.io/?EIO=4&transport=websocket&sid=abc123"]
