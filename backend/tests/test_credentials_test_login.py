import uuid

import httpx

from app.agents.http_client import AuthenticatedSession, ScopedHttpClient, ScopeViolationError
from app.api.routes.credentials import _get_following_redirects, _test_url_for
from app.models.project import ScopeEntry
from app.models.target import Target
from tests.conftest import session_scope


def test_test_url_for_prefers_explicit_base_url():
    target = Target(version_id=uuid.uuid4(), host="example.test", port=8443, base_url="https://example.test:8443")
    assert _test_url_for(target) == "https://example.test:8443"


def test_test_url_for_builds_https_url_when_no_base_url_and_no_port():
    target = Target(version_id=uuid.uuid4(), host="example.test", port=None, base_url=None)
    assert _test_url_for(target) == "https://example.test"


def test_test_url_for_uses_http_for_port_80():
    target = Target(version_id=uuid.uuid4(), host="example.test", port=80, base_url=None)
    assert _test_url_for(target) == "http://example.test"


def test_test_url_for_includes_nonstandard_port():
    target = Target(version_id=uuid.uuid4(), host="example.test", port=8080, base_url=None)
    assert _test_url_for(target) == "https://example.test:8080"


async def test_follows_redirect_to_spa_entry_point_and_reports_final_status(db_adapter):
    # The exact real-world case that motivated this: `/` redirecting to
    # the app's actual SPA entry point is normal, not a login failure —
    # the old bare client.get() reported the 302 itself as "not 2xx,
    # credential may be invalid", which was simply wrong.
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == "https://accountmanager.staging.msis.dev/":
            return httpx.Response(302, headers={"location": "/web/index.html"})
        if str(request.url) == "https://accountmanager.staging.msis.dev/web/index.html":
            return httpx.Response(200, text="ok")
        return httpx.Response(404)

    async with session_scope(db_adapter) as session:
        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[ScopeEntry(host="accountmanager.staging.msis.dev", port=443, in_scope=True)],
            db_session=session,
            transport=httpx.MockTransport(handler),
        )
        auth_session = AuthenticatedSession(credential_set_id=uuid.uuid4())

        response = await _get_following_redirects(
            client, "https://accountmanager.staging.msis.dev/", session=auth_session
        )

        assert str(response.url) == "https://accountmanager.staging.msis.dev/web/index.html"
        assert response.status_code == 200
        await client.aclose()


async def test_stops_at_a_genuine_non_redirect_failure(db_adapter):
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(401)

    async with session_scope(db_adapter) as session:
        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[ScopeEntry(host="example.test", port=443, in_scope=True)],
            db_session=session,
            transport=httpx.MockTransport(handler),
        )
        auth_session = AuthenticatedSession(credential_set_id=uuid.uuid4())

        response = await _get_following_redirects(client, "https://example.test/", session=auth_session)

        assert response.status_code == 401
        await client.aclose()


async def test_redirect_outside_scope_raises_scope_violation(db_adapter):
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://outside-scope.test/"})

    async with session_scope(db_adapter) as session:
        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[ScopeEntry(host="example.test", port=443, in_scope=True)],
            db_session=session,
            transport=httpx.MockTransport(handler),
        )
        auth_session = AuthenticatedSession(credential_set_id=uuid.uuid4())

        try:
            await _get_following_redirects(client, "https://example.test/", session=auth_session)
            raise AssertionError("expected ScopeViolationError")
        except ScopeViolationError:
            pass
        finally:
            await client.aclose()
