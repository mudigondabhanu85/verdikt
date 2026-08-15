import uuid

import httpx

from app.agents.http_client import ScopedHttpClient
from app.agents.recon import ReconAgent
from app.models.project import ScopeEntry
from app.models.target import Target
from tests.conftest import session_scope

PAGES = {
    "http://site.test/": (
        "text/html",
        '<html><body><a href="/about">About</a> <a href="/contact">Contact</a> '
        '<a href="/search?q=widgets">Search</a> <a href="/login">Login</a> '
        '<a href="http://evil.test/">Evil</a></body></html>',
    ),
    "http://site.test/about": (
        "text/html",
        '<html><body><a href="/deep/page">Deep</a></body></html>',
    ),
    "http://site.test/contact": ("text/html", "<html><body>Contact us</body></html>"),
    "http://site.test/deep/page": ("text/html", "<html><body>Deep page</body></html>"),
    "http://site.test/search?q=widgets": ("text/html", "<html><body>Results for widgets</body></html>"),
    "http://site.test/login": (
        "text/html",
        '<html><body><form method="POST" action="/do-login">'
        '<input type="text" name="username">'
        '<input type="password" name="password">'
        '<input type="hidden" name="csrf" value="tok123">'
        "</form></body></html>",
    ),
    "http://site.test/robots.txt": ("text/plain", "User-agent: *\nDisallow: /secret\n"),
    "http://site.test/secret": ("text/html", "<html><body>Secret area</body></html>"),
    "http://site.test/sitemap.xml": (
        "application/xml",
        "<urlset><url><loc>http://site.test/from-sitemap</loc></url></urlset>",
    ),
    "http://site.test/from-sitemap": ("text/html", "<html><body>From sitemap</body></html>"),
}


def _handler(request: httpx.Request) -> httpx.Response:
    url = str(request.url)
    if url in PAGES:
        content_type, body = PAGES[url]
        return httpx.Response(200, headers={"content-type": content_type}, text=body)
    return httpx.Response(404, text="not found")


async def test_recon_agent_discovers_endpoints_and_respects_scope(db_adapter):
    async with session_scope(db_adapter) as session:
        version_id = uuid.uuid4()
        scope_entries = [ScopeEntry(host="site.test", port=80, in_scope=True)]
        client = ScopedHttpClient(
            version_id=version_id,
            scope_entries=scope_entries,
            db_session=session,
            transport=httpx.MockTransport(_handler),
        )
        target = Target(host="site.test", port=80, base_url="http://site.test/")

        agent = ReconAgent(client, [target])
        discovered = await agent.run()

        assert "http://site.test/" in discovered
        assert "http://site.test/about" in discovered
        assert "http://site.test/contact" in discovered
        assert "http://site.test/deep/page" in discovered
        assert "http://site.test/secret" in discovered  # via robots.txt Disallow
        assert "http://site.test/from-sitemap" in discovered  # via sitemap.xml
        assert not any("evil.test" in url for url in discovered)

        await client.aclose()


async def test_recon_agent_respects_max_pages_bound(db_adapter):
    async with session_scope(db_adapter) as session:
        version_id = uuid.uuid4()
        scope_entries = [ScopeEntry(host="site.test", port=80, in_scope=True)]
        client = ScopedHttpClient(
            version_id=version_id,
            scope_entries=scope_entries,
            db_session=session,
            transport=httpx.MockTransport(_handler),
        )
        target = Target(host="site.test", port=80, base_url="http://site.test/")
        agent = ReconAgent(client, [target])
        agent.MAX_PAGES = 2

        discovered = await agent.run()
        assert len(discovered) <= 2

        await client.aclose()


async def test_recon_agent_discovers_query_params_and_forms(db_adapter):
    async with session_scope(db_adapter) as session:
        version_id = uuid.uuid4()
        scope_entries = [ScopeEntry(host="site.test", port=80, in_scope=True)]
        client = ScopedHttpClient(
            version_id=version_id,
            scope_entries=scope_entries,
            db_session=session,
            transport=httpx.MockTransport(_handler),
        )
        target = Target(host="site.test", port=80, base_url="http://site.test/")

        agent = ReconAgent(client, [target])
        await agent.run()

        params = agent.discovered_parameters
        search_params = [p for p in params if p.name == "q"]
        assert len(search_params) == 1
        assert search_params[0].url == "http://site.test/search?q=widgets"
        assert search_params[0].method == "GET"
        assert search_params[0].sample_value == "widgets"

        forms = agent.discovered_forms
        login_forms = [f for f in forms if f.action_url == "http://site.test/do-login"]
        assert len(login_forms) == 1
        form = login_forms[0]
        assert form.method == "POST"
        field_names = {f.name for f in form.fields}
        assert field_names == {"username", "password", "csrf"}
        password_field = next(f for f in form.fields if f.name == "password")
        assert password_field.type == "password"

        await client.aclose()
