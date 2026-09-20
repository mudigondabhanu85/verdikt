import asyncio
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urljoin, urlsplit

import httpx
from bs4 import BeautifulSoup

from app.agents.http_client import AuthenticatedSession, ScopedHttpClient, ScopeViolationError
from app.config import get_settings
from app.models.target import Target

_ROBOTS_DISALLOW_RE = re.compile(r"^\s*Disallow:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_SITEMAP_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)
# A classic crawler pitfall, live-found against DVWA: an authenticated
# crawl that follows every <a href> indiscriminately eventually clicks
# "Logout" — which, since every agent node shares one AuthenticatedSession
# per credential set, destroys the session for every *other* agent still
# relying on it mid-scan, not just this crawl. The fetch appears to
# succeed fine (a clean 200/302, no exception) and the crawl itself never
# notices anything wrong — the damage only shows up later, silently, as
# every other authenticated probe suddenly landing on the login redirect
# instead of the page it asked for.
_LOGOUT_LINK_RE = re.compile(r"log[\s_-]?out|sign[\s_-]?out", re.IGNORECASE)
# Looks for ws(s):// literals in any fetched page or script body (e.g.
# inside a `new WebSocket("wss://...")` call) — good enough to surface
# an endpoint for app.agents.websocket_security without needing to
# actually execute the page's JS.
_WEBSOCKET_URL_RE = re.compile(r"wss?://[^\s\"'<>\\]+")
# The two standard browser AJAX call shapes — fetch(url, ...) and
# XMLHttpRequest's .open(method, url) — good enough to surface an
# endpoint that only exists as a JS string literal, never linked from
# any <a href> or <form>, without needing to actually execute the
# page's JS (same "good enough" bar as _WEBSOCKET_URL_RE above). Only
# fires against script content this crawl actually fetched — see
# _extract_script_srcs, which queues external <script src> files as
# their own crawl targets specifically so their body reaches this.
# Real gap this closes: DVWA's own "API" and "Authorisation Bypass"
# pages call `/vulnerabilities/api/v2/user/` and
# `get_user_data.php`/`change_user_details.php` purely from an external
# .js file with no HTML reference anywhere — invisible to every
# check that depends on discovered_endpoints until this existed.
_JS_ENDPOINT_URL_RE = re.compile(
    r"""fetch\(\s*['"]([^'"]+)['"]"""
    r"""|\.open\(\s*['"](?:GET|POST|PUT|DELETE|PATCH)['"]\s*,\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)
# The same two call shapes, but via a variable holding the URL rather
# than a string literal in the call itself — e.g.
# `const url = '/api/v2/user/'; fetch(url, {...})`, DVWA's own "API"
# page's real code. _JS_ENDPOINT_URL_RE alone misses this; resolving the
# variable needs a second pass matching its assignment separately.
_JS_URL_ASSIGNMENT_RE = re.compile(
    r"""(?:const|let|var)\s+(\w+)\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE
)
_JS_ENDPOINT_URL_VARIABLE_RE = re.compile(
    r"""fetch\(\s*(\w+)\b"""
    r"""|\.open\(\s*['"](?:GET|POST|PUT|DELETE|PATCH)['"]\s*,\s*(\w+)\b""",
    re.IGNORECASE,
)
# A quoted relative-URL-like string inside an onclick handler — e.g.
# onclick="javascript:popUp('session-input.php')" or
# onclick="window.open('/help/topic.html')". A plain <a href> crawl
# structurally cannot see pages only reachable this way: DVWA's own
# SQL Injection page at "High" difficulty (§14) replaces its normal
# <input>/<form> entirely with exactly this pattern (a link that opens a
# popup which POSTs into a session variable the main page's query later
# uses) — not a filter or sanitizer, a genuine crawl-discovery gap that
# left the popup's own form (and the second-order SQL injection behind
# it) completely invisible to every check that depends on recon's own
# forms/endpoints lists. Requires a recognizable web page extension so
# this doesn't misfire on the many onclick handlers that reference
# something other than a URL at all (a CSS class, an analytics event
# name, a DOM id).
_ONCLICK_URL_RE = re.compile(
    r"""(['"])([\w.\-/]+\.(?:php|html?|aspx?|jsp)(?:\?[^'"]*)?)\1""", re.IGNORECASE
)


@dataclass
class FormField:
    name: str
    type: str  # the input's type= attribute, e.g. "text", "password", "hidden"


@dataclass
class FormInfo:
    action_url: str
    method: str  # "GET" or "POST"
    fields: list[FormField] = field(default_factory=list)


@dataclass
class DiscoveredParameter:
    """One (submission target, parameter) pair the Injection/XSS agents can
    probe — either a query-string key already observed on a crawled URL,
    or a non-hidden <form> field. HTML-only surface (see Phase 2 plan's
    NoSQLi scope note for why JSON API bodies aren't covered).
    """

    url: str
    method: str
    name: str
    sample_value: str = ""


def _looks_html(response: httpx.Response) -> bool:
    return "html" in response.headers.get("content-type", "").lower()


def _extract_links(base_url: str, soup: BeautifulSoup) -> tuple[list[str], list[str]]:
    """Returns (links_to_follow, logout_links). A logout link is never
    added to links_to_follow (see the module-level comment on
    _LOGOUT_LINK_RE for why — following it would kill the one shared
    session every other concurrent agent depends on), but it must not
    just vanish either: app.agents.session_invalidation needs a real
    logout URL to test, and until this returned it separately, nothing
    anywhere ever captured one — the check would have been silently dead
    code, unable to find a logout link no matter how obviously one
    existed on the page, precisely because this function's whole job is
    to hide logout links from everything that follows links.
    """
    links = []
    logout_links = []
    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()
        if href.startswith(("javascript:", "mailto:", "tel:", "#")):
            continue
        if _LOGOUT_LINK_RE.search(href) or _LOGOUT_LINK_RE.search(tag.get_text()):
            logout_links.append(urljoin(base_url, href))
            continue
        links.append(urljoin(base_url, href))

    # See _ONCLICK_URL_RE's docstring — any element (not just <a>) can
    # trigger a popup/navigation via onclick with no real <a href> at
    # all. Same logout-link carve-out as above applies here too.
    for tag in soup.find_all(onclick=True):
        for href in _ONCLICK_URL_RE.findall(tag["onclick"]):
            href = href[1]  # (quote_char, url) — see the capture groups above
            if _LOGOUT_LINK_RE.search(href):
                logout_links.append(urljoin(base_url, href))
                continue
            links.append(urljoin(base_url, href))

    return links, logout_links


def extract_forms(base_url: str, soup: BeautifulSoup) -> list[FormInfo]:
    forms = []
    for form_tag in soup.find_all("form"):
        action = form_tag.get("action") or base_url
        method = (form_tag.get("method") or "GET").strip().upper()
        fields = []
        for input_tag in form_tag.find_all(["input", "textarea", "select"]):
            name = input_tag.get("name")
            if not name:
                continue
            field_type = input_tag.get("type", "text") if input_tag.name == "input" else "text"
            fields.append(FormField(name=name, type=field_type))
        forms.append(FormInfo(action_url=urljoin(base_url, action), method=method, fields=fields))
    return forms


def _extract_websocket_urls(text: str) -> list[str]:
    return list(dict.fromkeys(_WEBSOCKET_URL_RE.findall(text)))


def _extract_js_endpoint_urls(base_url: str, text: str) -> list[str]:
    literals = [match.group(1) or match.group(2) for match in _JS_ENDPOINT_URL_RE.finditer(text)]

    variable_values = dict(_JS_URL_ASSIGNMENT_RE.findall(text))
    for match in _JS_ENDPOINT_URL_VARIABLE_RE.finditer(text):
        var_name = match.group(1) or match.group(2)
        if var_name in variable_values:
            literals.append(variable_values[var_name])

    urls = [
        urljoin(base_url, url)
        for url in literals
        if url and not url.startswith(("data:", "javascript:", "about:", "#"))
    ]
    return list(dict.fromkeys(urls))


def _extract_script_srcs(base_url: str, soup: BeautifulSoup) -> list[str]:
    """External <script src> files — queued as their own crawl targets
    (same frontier, same scope/depth/page budget as any other link) so
    their body is actually fetched and reaches _extract_js_endpoint_urls/
    _extract_websocket_urls, both of which only ever scan text this
    crawl already has in hand."""
    return [
        urljoin(base_url, tag["src"].strip())
        for tag in soup.find_all("script", src=True)
        if tag["src"].strip()
    ]


def _extract_query_params(url: str) -> list[DiscoveredParameter]:
    query = urlsplit(url).query
    if not query:
        return []
    parsed = parse_qs(query, keep_blank_values=True)
    return [
        DiscoveredParameter(url=url, method="GET", name=name, sample_value=(values[0] if values else ""))
        for name, values in parsed.items()
    ]


def _seed_urls_for_target(target: Target) -> list[str]:
    if target.base_url:
        base = target.base_url.rstrip("/") + "/"
    else:
        scheme = "https" if target.port == 443 else "http"
        port_suffix = f":{target.port}" if target.port and target.port not in (80, 443) else ""
        base = f"{scheme}://{target.host}{port_suffix}/"
    return [base, urljoin(base, "/robots.txt"), urljoin(base, "/sitemap.xml")]


class ReconAgent:
    """Same-origin crawl from each in-scope Target, bounded (§1.2
    safe-by-default) rather than unbounded even against fully authorized
    targets: configurable depth/page limits (Settings.crawl_max_depth/
    crawl_max_pages, default 6/300), modest concurrency. run() returns the
    endpoints discovered (status < 400); discovered_parameters and
    discovered_forms are populated as a side effect of the same crawl for
    later agents (Injection/XSS probe parameters, login auto-discovery).

    An optional `session` crawls authenticated instead of anonymous — see
    app.agents.graph's authenticated_recon_node, which re-runs this crawl
    once a login succeeds. Without it, this crawl only ever sees whatever
    an unauthenticated visitor sees (the login page, public static
    assets); a real app's vulnerability surface almost entirely lives
    behind that login wall, and a purely pre-login crawl was found (via a
    live DVWA scan) to discover exactly one <form> — login.php's own —
    leaving injection/XSS/CSRF/access-control/etc. with nothing to probe
    beyond whatever a traffic import happened to already seed.
    """

    # Raised 2026-09 from 40/2 — real apps routinely have more than 40
    # pages or a link structure deeper than 2 hops from robots.txt/
    # sitemap.xml/the homepage, so the crawl was silently stopping well
    # short of "the entire application" for anything beyond a small
    # demo target. Still bounded (§1.2 safe-by-default — never truly
    # unbounded even against a fully authorized target), just a much
    # more realistic ceiling — and configurable (Settings.crawl_max_pages/
    # crawl_max_depth) rather than hardcoded, since this is a real
    # scan-duration/request-volume tradeoff a deployment may want to dial
    # back for a smaller or rate-sensitive target. These class-level
    # values are just the fallback defaults if unset. CONCURRENCY
    # unchanged since it controls request rate against the live target,
    # not coverage.
    MAX_PAGES = 300
    MAX_DEPTH = 6
    CONCURRENCY = 5

    def __init__(
        self,
        client: ScopedHttpClient,
        targets: list[Target],
        *,
        session: AuthenticatedSession | None = None,
        extra_seed_urls: list[str] | None = None,
    ):
        self._client = client
        self._targets = targets
        self._session = session
        # Traffic-imported and AI-recon-planner-suggested URLs (see
        # app.agents.graph's recon_node) — previously only ever unioned
        # into the *result* list after this crawl finished, never
        # explored *from*, so any page only reachable by following a
        # link on one of them was invisible to Verdikt no matter how
        # much traffic was imported. Seeding them into the frontier
        # here means the crawl actually continues from them, same as
        # any page it found itself.
        #
        # Real, live-found bug: an AI-suggested candidate path (e.g.
        # app.agents.recon_planner guessing "/logout.php" as a plausible
        # unlinked page) bypasses _extract_links's own logout carve-out
        # entirely, since that only filters <a href> links found *inside*
        # an already-fetched page, never a seed handed in directly. This
        # is the same class of hazard for any future extra_seed_urls
        # caller too, so it's filtered here — the frontier's own choke
        # point — rather than trusting every caller to remember it.
        self._extra_seed_urls = [u for u in (extra_seed_urls or []) if not _LOGOUT_LINK_RE.search(u)]
        settings = get_settings()
        self.MAX_PAGES = settings.crawl_max_pages
        self.MAX_DEPTH = settings.crawl_max_depth
        self._semaphore = asyncio.Semaphore(self.CONCURRENCY)
        self.discovered_parameters: list[DiscoveredParameter] = []
        self.discovered_forms: list[FormInfo] = []
        # Every successfully-fetched response from this crawl, keyed by
        # URL — reused by FingerprintAgent (§10 smart scan) so tech-stack
        # detection costs zero extra requests instead of re-fetching.
        self.discovered_responses: dict[str, httpx.Response] = {}
        self.discovered_websocket_endpoints: list[str] = []
        self.discovered_api_endpoints: list[str] = []
        # See _extract_links's docstring — captured separately from
        # discovered_endpoints precisely because a logout link is never
        # allowed into that list at all.
        self.discovered_logout_urls: list[str] = []

    async def _fetch(self, url: str) -> httpx.Response | None:
        async with self._semaphore:
            try:
                return await self._client.get(url, session=self._session)
            except (ScopeViolationError, httpx.HTTPError):
                return None

    async def run(self) -> list[str]:
        discovered = self.discovered_responses
        visited: set[str] = set()

        frontier: list[str] = []
        for target in self._targets:
            frontier.extend(_seed_urls_for_target(target))
        frontier.extend(self._extra_seed_urls)

        depth = 0
        while frontier and depth <= self.MAX_DEPTH and len(visited) < self.MAX_PAGES:
            batch = [u for u in dict.fromkeys(frontier) if u not in visited]
            batch = batch[: self.MAX_PAGES - len(visited)]
            if not batch:
                break

            responses = await asyncio.gather(*(self._fetch(u) for u in batch))

            next_frontier: list[str] = []
            for url, response in zip(batch, responses):
                visited.add(url)
                if response is None:
                    continue
                if response.status_code < 400:
                    discovered[url] = response
                    self.discovered_parameters.extend(_extract_query_params(url))
                    for ws_url in _extract_websocket_urls(response.text):
                        if ws_url not in self.discovered_websocket_endpoints:
                            self.discovered_websocket_endpoints.append(ws_url)
                    for api_url in _extract_js_endpoint_urls(url, response.text):
                        if api_url not in self.discovered_api_endpoints:
                            self.discovered_api_endpoints.append(api_url)
                next_frontier.extend(self._follow_up_links(url, response))

            frontier = next_frontier
            depth += 1

        return list(discovered.keys())

    def _follow_up_links(self, url: str, response: httpx.Response) -> list[str]:
        path = urlsplit(url).path
        # ScopedHttpClient deliberately never auto-follows redirects
        # (follow_redirects=False) so every hop stays individually
        # scope-checked — but that means a redirect target has to be
        # queued as its own frontier entry, or the crawl just stops dead
        # at the redirect. A very common real-world pattern this was
        # silently blind to: an app whose "/" 302s an unauthenticated
        # visitor straight to a login page (DVWA's login.php, and
        # countless real apps) — the crawl never saw the login form at
        # all, so login-form auto-discovery had nothing to find.
        if response.is_redirect:
            location = response.headers.get("location")
            if location:
                return [urljoin(url, location)]
            return []
        if path == "/robots.txt" and response.status_code < 400:
            return [urljoin(url, m) for m in _ROBOTS_DISALLOW_RE.findall(response.text)]
        if path == "/sitemap.xml" and response.status_code < 400:
            return _SITEMAP_LOC_RE.findall(response.text)
        if _looks_html(response):
            soup = BeautifulSoup(response.text, "html.parser")
            self.discovered_forms.extend(extract_forms(url, soup))
            links, logout_links = _extract_links(url, soup)
            for logout_url in logout_links:
                if logout_url not in self.discovered_logout_urls:
                    self.discovered_logout_urls.append(logout_url)
            return links + _extract_script_srcs(url, soup)
        return []
