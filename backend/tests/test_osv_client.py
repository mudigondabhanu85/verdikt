import httpx

from app.integrations.osv.client import OsvClient, OsvLookupError


def _handler(request: httpx.Request) -> httpx.Response:
    body = request.read()
    import json

    payload = json.loads(body)
    if payload["package"]["name"] == "jquery" and payload["version"] == "1.7.0":
        return httpx.Response(200, json={"vulns": [{"id": "GHSA-abcd-1234"}]})
    return httpx.Response(200, json={"vulns": []})


async def test_known_vulnerable_version_returns_vulns():
    client = OsvClient(transport=httpx.MockTransport(_handler))

    vulns = await client.query_npm_package(name="jquery", version="1.7.0")

    assert vulns == [{"id": "GHSA-abcd-1234"}]


async def test_safe_version_returns_empty_list():
    client = OsvClient(transport=httpx.MockTransport(_handler))

    vulns = await client.query_npm_package(name="jquery", version="3.7.1")

    assert vulns == []


async def test_non_200_raises_lookup_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    client = OsvClient(transport=httpx.MockTransport(handler))

    try:
        await client.query_npm_package(name="jquery", version="1.7.0")
        assert False, "expected OsvLookupError"
    except OsvLookupError:
        pass
