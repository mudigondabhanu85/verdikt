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
    "http://site.test/deep/page": (
        "text/html",
        '<html><body>Deep page<script>var s = new WebSocket("wss://site.test/live-feed");'
        "</script></body></html>",
    ),
    "http://site.test/dashboard/": (
        "text/html",
        '<html><body><a href="/logout.php">Logout</a> <a href="/account">Account</a></body></html>',
    ),
    "http://site.test/logout.php": ("text/html", "<html><body>Logged out</body></html>"),
    "http://site.test/account": ("text/html", "<html><body>Account settings</body></html>"),
    "http://site.test/sqli/": (
        "text/html",
        '<html><body>Click <a href="#" onclick="javascript:popUp(\'session-input.php\');'
        'return false;">here to change your ID</a>.'
        '<button onclick="trackEvent(\'not-a-url\')">Track</button>'
        "</body></html>",
    ),
    "http://site.test/sqli/session-input.php": (
        "text/html",
        '<html><body><form method="POST" action="#"><input type="text" name="id">'
        '<input type="submit" name="Submit" value="Submit"></form></body></html>',
    ),
    "http://site.test/api/": (
        "text/html",
        '<html><body><script src="app.js"></script></body></html>',
    ),
    "http://site.test/api/app.js": (
        "application/javascript",
        "function load() { fetch('/api/v2/user/').then(r => r.json()); }\n"
        "var xhr = new XMLHttpRequest(); xhr.open('GET', 'get_user_data.php', true); xhr.send();",
    ),
    "http://site.test/inline-api/": (
        "text/html",
        "<html><body><script>"
        "const url = '/api/v3/order/';\n"
        "fetch(url, { method: 'GET' });"
        "</script></body></html>",
    ),
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


async def test_recon_agent_never_follows_logout_links(db_adapter):
    # A real, live-found bug: crawling every <a href> indiscriminately
    # eventually clicks "Logout" — since every agent node shares one
    # AuthenticatedSession per credential set, that destroys the session
    # for every *other* agent still relying on it mid-scan, not just this
    # crawl (see app.agents.recon's _LOGOUT_LINK_RE docstring).
    async with session_scope(db_adapter) as session:
        version_id = uuid.uuid4()
        scope_entries = [ScopeEntry(host="site.test", port=80, in_scope=True)]
        client = ScopedHttpClient(
            version_id=version_id,
            scope_entries=scope_entries,
            db_session=session,
            transport=httpx.MockTransport(_handler),
        )
        target = Target(host="site.test", port=80, base_url="http://site.test/dashboard")

        agent = ReconAgent(client, [target])
        discovered = await agent.run()

        assert "http://site.test/account" in discovered
        assert "http://site.test/logout.php" not in discovered
        # Never followed, but not silently dropped either —
        # app.agents.session_invalidation needs a real logout URL to
        # test, captured separately from the crawled-endpoints list.
        assert agent.discovered_logout_urls == ["http://site.test/logout.php"]

        await client.aclose()


async def test_recon_agent_never_fetches_a_logout_shaped_extra_seed_url(db_adapter):
    """Same hazard as test_recon_agent_never_follows_logout_links, but for
    a URL handed in directly via extra_seed_urls (app.agents.recon_planner's
    AI-suggested-path mechanism is the real caller) rather than discovered
    via an <a href> mid-crawl. _extract_links's own carve-out only ever
    protects links found *inside* an already-fetched page — a seed passed
    straight in bypasses it entirely, so this must be filtered at
    __init__ time instead. The handler raises if logout.php is ever
    actually requested, not just asserting it's absent from the result.
    """
    def handler(request: httpx.Request) -> httpx.Response:
        if "logout" in str(request.url):
            raise AssertionError(f"logout-shaped seed URL was fetched: {request.url}")
        return httpx.Response(200, text="<html></html>", request=request)

    async with session_scope(db_adapter) as session:
        version_id = uuid.uuid4()
        scope_entries = [ScopeEntry(host="site.test", port=80, in_scope=True)]
        client = ScopedHttpClient(
            version_id=version_id,
            scope_entries=scope_entries,
            db_session=session,
            transport=httpx.MockTransport(handler),
        )
        target = Target(host="site.test", port=80, base_url="http://site.test/")

        agent = ReconAgent(client, [target], extra_seed_urls=["http://site.test/logout.php"])
        discovered = await agent.run()

        assert "http://site.test/logout.php" not in discovered

        await client.aclose()


async def test_recon_agent_follows_onclick_popup_links(db_adapter):
    """The real, live-found DVWA High gap this exists for (§14): SQL
    Injection at that difficulty replaces its normal <form> entirely
    with a link whose ONLY reference to the popup page lives in an
    onclick attribute, never a real <a href> — a plain href-based crawl
    is structurally blind to it, which meant the popup's own form (and
    the second-order SQL injection behind it) was completely
    undiscoverable no matter how the injection agent itself worked.
    """
    async with session_scope(db_adapter) as session:
        version_id = uuid.uuid4()
        scope_entries = [ScopeEntry(host="site.test", port=80, in_scope=True)]
        client = ScopedHttpClient(
            version_id=version_id,
            scope_entries=scope_entries,
            db_session=session,
            transport=httpx.MockTransport(_handler),
        )
        target = Target(host="site.test", port=80, base_url="http://site.test/sqli/")

        agent = ReconAgent(client, [target])
        discovered = await agent.run()

        assert "http://site.test/sqli/session-input.php" in discovered
        forms = [f for f in agent.discovered_forms if f.action_url.startswith("http://site.test/sqli/session-input.php")]
        assert len(forms) == 1
        assert {f.name for f in forms[0].fields} == {"id", "Submit"}

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

        assert agent.discovered_websocket_endpoints == ["wss://site.test/live-feed"]

        await client.aclose()


async def test_recon_agent_discovers_endpoints_referenced_only_from_external_js(db_adapter):
    """A real gap this closes: an endpoint referenced only inside an
    external <script src> file (fetch()/XMLHttpRequest.open() calls),
    never linked from any <a href> or <form> — invisible to a plain
    HTML crawl no matter how thorough, which left DVWA's own "API" and
    "Authorisation Bypass" pages completely untestable (see
    app.agents.recon's _JS_ENDPOINT_URL_RE docstring)."""
    async with session_scope(db_adapter) as session:
        version_id = uuid.uuid4()
        scope_entries = [ScopeEntry(host="site.test", port=80, in_scope=True)]
        client = ScopedHttpClient(
            version_id=version_id,
            scope_entries=scope_entries,
            db_session=session,
            transport=httpx.MockTransport(_handler),
        )
        target = Target(host="site.test", port=80, base_url="http://site.test/api/")

        agent = ReconAgent(client, [target])
        discovered = await agent.run()

        assert "http://site.test/api/app.js" in discovered
        assert set(agent.discovered_api_endpoints) == {
            "http://site.test/api/v2/user/",
            "http://site.test/api/get_user_data.php",
        }

        await client.aclose()


async def test_recon_agent_resolves_fetch_url_held_in_a_variable(db_adapter):
    """The other real, common shape besides a string literal passed
    straight to fetch()/xhr.open() — DVWA's own "API" page's real code
    does `const url = '/api/v2/user/'; fetch(url, {...})`, which
    _JS_ENDPOINT_URL_RE alone can't see since the literal never appears
    inside the fetch(...) call itself."""
    async with session_scope(db_adapter) as session:
        version_id = uuid.uuid4()
        scope_entries = [ScopeEntry(host="site.test", port=80, in_scope=True)]
        client = ScopedHttpClient(
            version_id=version_id,
            scope_entries=scope_entries,
            db_session=session,
            transport=httpx.MockTransport(_handler),
        )
        target = Target(host="site.test", port=80, base_url="http://site.test/inline-api/")

        agent = ReconAgent(client, [target])
        await agent.run()

        assert agent.discovered_api_endpoints == ["http://site.test/api/v3/order/"]

        await client.aclose()
