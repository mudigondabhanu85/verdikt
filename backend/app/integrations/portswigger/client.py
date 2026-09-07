"""Fetches curated vulnerability write-ups from PortSwigger's public Web
Security Academy topic pages — a native port of the standalone VGS tool's
scripts/portswigger_to_excel.py (same SEED_URLS list, same <h1>/meta-
description scrape), used by the "Load from PortSwigger" action in
app.api.routes.vgs_vulnerabilities instead of that tool's offline
scrape-to-Excel-then-upload round trip.
"""

from dataclasses import dataclass

import httpx
from bs4 import BeautifulSoup


class PortswigerFetchError(RuntimeError):
    pass


# Ported verbatim from the standalone VGS tool's scripts/portswigger_to_excel.py SEED_URLS.
SEED_TOPIC_URLS = [
    "https://portswigger.net/web-security/sql-injection",
    "https://portswigger.net/web-security/cross-site-scripting",
    "https://portswigger.net/web-security/ssrf",
    "https://portswigger.net/web-security/authentication",
    "https://portswigger.net/web-security/access-control",
    "https://portswigger.net/web-security/path-traversal",
    "https://portswigger.net/web-security/file-upload",
    "https://portswigger.net/web-security/request-smuggling",
    "https://portswigger.net/web-security/web-cache-poisoning",
    "https://portswigger.net/web-security/csrf",
    "https://portswigger.net/web-security/os-command-injection",
    "https://portswigger.net/web-security/xxe",
    "https://portswigger.net/web-security/open-redirects",
]

_HEADERS = {"User-Agent": "Mozilla/5.0 (Verdikt VGS report-builder; contact: security@verdikt.local)"}


@dataclass
class PortswigerTopic:
    title: str
    description: str
    url: str


async def fetch_topics(
    urls: list[str] | None = None,
    *,
    transport: httpx.BaseTransport | None = None,
    timeout: float = 25.0,
) -> list[PortswigerTopic]:
    """One topic per successfully-fetched URL — a single broken/unreachable
    page is skipped rather than failing the whole batch (best-effort, same
    shape as app.notifications.vgs_push's per-config catch-and-continue).
    Raises only if every URL failed, so a genuine outage is still surfaced
    rather than silently reporting zero results as success."""
    target_urls = urls if urls is not None else SEED_TOPIC_URLS
    topics: list[PortswigerTopic] = []
    async with httpx.AsyncClient(transport=transport, timeout=timeout, headers=_HEADERS) as client:
        for url in target_urls:
            try:
                response = await client.get(url)
                response.raise_for_status()
            except httpx.HTTPError:
                continue
            soup = BeautifulSoup(response.text, "html.parser")
            h1 = soup.find("h1")
            title = h1.get_text(strip=True) if h1 else url
            meta_desc = soup.find("meta", attrs={"name": "description"})
            description = meta_desc["content"].strip() if meta_desc and meta_desc.get("content") else ""
            topics.append(PortswigerTopic(title=title, description=description, url=url))

    if not topics and target_urls:
        raise PortswigerFetchError("Could not fetch any PortSwigger topic pages")
    return topics
