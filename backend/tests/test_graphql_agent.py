import json
import uuid

import httpx

from app.agents.graphql import GraphQLAgent
from app.agents.http_client import ScopedHttpClient
from app.models.project import ScopeEntry
from tests.conftest import session_scope


def _introspection_enabled_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/graphql" and request.method == "POST":
        body = json.loads(request.content.decode())
        if "__schema" in body.get("query", ""):
            return httpx.Response(
                200,
                json={
                    "data": {
                        "__schema": {
                            "queryType": {"name": "Query"},
                            "types": [{"name": "Query"}, {"name": "User"}, {"name": "Order"}],
                        }
                    }
                },
            )
    return httpx.Response(404)


def _introspection_disabled_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/graphql" and request.method == "POST":
        return httpx.Response(
            200,
            json={"errors": [{"message": "GraphQL introspection is not allowed"}]},
        )
    return httpx.Response(404)


async def _run_agent(db_adapter, handler, endpoints):
    async with session_scope(db_adapter) as session:
        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[ScopeEntry(host="site.test", port=80, in_scope=True)],
            db_session=session,
            transport=httpx.MockTransport(handler),
        )
        agent = GraphQLAgent(
            client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
        )
        findings = await agent.run(endpoints)
        await client.aclose()
        return findings


async def test_introspection_enabled_is_flagged(db_adapter):
    findings = await _run_agent(
        db_adapter, _introspection_enabled_handler, ["http://site.test/"]
    )
    check_ids = {f.check_id for f in findings}
    assert "graphql-introspection-enabled" in check_ids
    finding = next(f for f in findings if f.check_id == "graphql-introspection-enabled")
    assert finding.severity == "Medium"
    assert "3 known types" in finding.technical_description


async def test_introspection_disabled_is_not_flagged(db_adapter):
    findings = await _run_agent(
        db_adapter, _introspection_disabled_handler, ["http://site.test/"]
    )
    assert findings == []


async def test_no_graphql_endpoint_at_all_is_not_flagged(db_adapter):
    findings = await _run_agent(db_adapter, lambda r: httpx.Response(404), ["http://site.test/"])
    assert findings == []
