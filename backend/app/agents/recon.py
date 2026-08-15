import asyncio
import re
from urllib.parse import urljoin, urlsplit

import httpx
from bs4 import BeautifulSoup

from app.agents.http_client import ScopedHttpClient, ScopeViolationError
from app.models.target import Target

_ROBOTS_DISALLOW_RE = re.compile(r"^\s*Disallow:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_SITEMAP_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)


def _looks_html(response: httpx.Response) -> bool:
    return "html" in response.headers.get("content-type", "").lower()


def _extract_links(base_url: str, html: str) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    links = []
    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()
        if href.startswith(("javascript:", "mailto:", "tel:", "#")):
            continue
        links.append(urljoin(base_url, href))
    return links


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
    targets: depth 2, max 40 pages, modest concurrency. Returns the
    endpoints discovered (status < 400) for the HeaderConfigAgent to check.
    """

    MAX_PAGES = 40
    MAX_DEPTH = 2
    CONCURRENCY = 5

    def __init__(self, client: ScopedHttpClient, targets: list[Target]):
        self._client = client
        self._targets = targets
        self._semaphore = asyncio.Semaphore(self.CONCURRENCY)

    async def _fetch(self, url: str) -> httpx.Response | None:
        async with self._semaphore:
            try:
                return await self._client.get(url)
            except (ScopeViolationError, httpx.HTTPError):
                return None

    async def run(self) -> list[str]:
        discovered: dict[str, httpx.Response] = {}
        visited: set[str] = set()

        frontier: list[str] = []
        for target in self._targets:
            frontier.extend(_seed_urls_for_target(target))

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
                next_frontier.extend(self._follow_up_links(url, response))

            frontier = next_frontier
            depth += 1

        return list(discovered.keys())

    def _follow_up_links(self, url: str, response: httpx.Response) -> list[str]:
        path = urlsplit(url).path
        if path == "/robots.txt" and response.status_code < 400:
            return [urljoin(url, m) for m in _ROBOTS_DISALLOW_RE.findall(response.text)]
        if path == "/sitemap.xml" and response.status_code < 400:
            return _SITEMAP_LOC_RE.findall(response.text)
        if _looks_html(response):
            return _extract_links(url, response.text)
        return []
