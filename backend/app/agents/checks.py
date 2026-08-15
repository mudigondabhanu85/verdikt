"""Deterministic detection logic for the Phase-1 check catalog
(app/checks/catalog.yaml). One small pure function per check id, each
taking a FetchedPage and returning zero or more CheckHit — no I/O, no
LLM calls, unit-testable against synthetic fixtures.
"""

import re
from dataclasses import dataclass, field
from typing import Callable

from bs4 import BeautifulSoup
from httpx import Headers


@dataclass
class FetchedPage:
    url: str
    status_code: int
    headers: Headers
    text: str
    scheme: str
    tls_version: str | None = None


@dataclass
class CheckHit:
    check_id: str
    affected_endpoint: str
    extra: dict = field(default_factory=dict)


def _set_cookie_headers(page: FetchedPage) -> list[str]:
    return page.headers.get_list("set-cookie")


def _cookie_attrs(raw_cookie: str) -> tuple[str, set[str], str | None]:
    """Returns (cookie_name, {lowercased attribute names present}, samesite_value)."""
    parts = [p.strip() for p in raw_cookie.split(";")]
    name = parts[0].split("=", 1)[0] if parts else ""
    attrs: set[str] = set()
    samesite_value = None
    for part in parts[1:]:
        key, _, value = part.partition("=")
        key_lower = key.strip().lower()
        attrs.add(key_lower)
        if key_lower == "samesite":
            samesite_value = value.strip()
    return name, attrs, samesite_value


def check_missing_hsts(page: FetchedPage) -> list[CheckHit]:
    if page.scheme != "https":
        return []
    if "strict-transport-security" in page.headers:
        return []
    return [CheckHit("missing-hsts", page.url)]


def check_missing_csp(page: FetchedPage) -> list[CheckHit]:
    if "content-security-policy" in page.headers:
        return []
    return [CheckHit("missing-csp", page.url)]


def check_missing_x_frame_options(page: FetchedPage) -> list[CheckHit]:
    if "x-frame-options" in page.headers:
        return []
    csp = page.headers.get("content-security-policy", "")
    if "frame-ancestors" in csp.lower():
        return []
    return [CheckHit("missing-x-frame-options", page.url)]


def check_missing_x_content_type_options(page: FetchedPage) -> list[CheckHit]:
    value = page.headers.get("x-content-type-options", "")
    if value.strip().lower() == "nosniff":
        return []
    return [CheckHit("missing-x-content-type-options", page.url)]


def check_missing_referrer_policy(page: FetchedPage) -> list[CheckHit]:
    if "referrer-policy" in page.headers:
        return []
    return [CheckHit("missing-referrer-policy", page.url)]


def check_missing_permissions_policy(page: FetchedPage) -> list[CheckHit]:
    if "permissions-policy" in page.headers:
        return []
    return [CheckHit("missing-permissions-policy", page.url)]


def check_cookie_missing_secure(page: FetchedPage) -> list[CheckHit]:
    if page.scheme != "https":
        return []
    hits = []
    for raw in _set_cookie_headers(page):
        name, attrs, _ = _cookie_attrs(raw)
        if "secure" not in attrs:
            hits.append(CheckHit("cookie-missing-secure", page.url, {"cookie_name": name}))
    return hits


def check_cookie_missing_httponly(page: FetchedPage) -> list[CheckHit]:
    hits = []
    for raw in _set_cookie_headers(page):
        name, attrs, _ = _cookie_attrs(raw)
        if "httponly" not in attrs:
            hits.append(CheckHit("cookie-missing-httponly", page.url, {"cookie_name": name}))
    return hits


def check_cookie_missing_samesite(page: FetchedPage) -> list[CheckHit]:
    hits = []
    for raw in _set_cookie_headers(page):
        name, attrs, value = _cookie_attrs(raw)
        if "samesite" not in attrs or (value or "").lower() == "none":
            hits.append(CheckHit("cookie-missing-samesite", page.url, {"cookie_name": name}))
    return hits


def check_server_version_disclosure(page: FetchedPage) -> list[CheckHit]:
    server = page.headers.get("server")
    powered_by = page.headers.get("x-powered-by")
    values = [v for v in (server, powered_by) if v]
    if not values:
        return []
    return [
        CheckHit("server-version-disclosure", page.url, {"server_value": " / ".join(values)})
    ]


_STACK_TRACE_PATTERNS = [
    re.compile(r"Traceback \(most recent call last\)", re.IGNORECASE),
    re.compile(r"at\s+[\w.$]+\(\w+\.java:\d+\)"),
    re.compile(r"Whitelabel Error Page"),
    re.compile(r"Fatal error:.*on line \d+", re.IGNORECASE),
    re.compile(r"System\.\w*Exception"),
    re.compile(r"Microsoft OLE DB Provider"),
    re.compile(r"ORA-\d{5}"),
    re.compile(r"Warning:\s+mysql_\w+\(\)"),
    re.compile(r"System\.Data\.SqlClient\.SqlException"),
    re.compile(r"at Object\.<anonymous>.*\(.*:\d+:\d+\)"),
]


def check_verbose_error_stack_trace(page: FetchedPage) -> list[CheckHit]:
    for pattern in _STACK_TRACE_PATTERNS:
        if pattern.search(page.text):
            return [CheckHit("verbose-error-stack-trace", page.url)]
    return []


def check_directory_listing_enabled(page: FetchedPage) -> list[CheckHit]:
    lowered = page.text.lower()
    if "index of /" in lowered and "parent directory" in lowered:
        return [CheckHit("directory-listing-enabled", page.url)]
    return []


def check_plaintext_http(page: FetchedPage) -> list[CheckHit]:
    if page.scheme == "http":
        return [CheckHit("plaintext-http", page.url)]
    return []


_WEAK_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def check_weak_tls_version(page: FetchedPage) -> list[CheckHit]:
    if page.scheme != "https" or not page.tls_version:
        return []
    if page.tls_version in _WEAK_TLS_VERSIONS:
        return [CheckHit("weak-tls-version", page.url, {"tls_version": page.tls_version})]
    return []


def check_autocomplete_enabled_password_field(page: FetchedPage) -> list[CheckHit]:
    content_type = page.headers.get("content-type", "")
    if "html" not in content_type.lower():
        return []
    soup = BeautifulSoup(page.text, "html.parser")
    for input_tag in soup.find_all("input", attrs={"type": "password"}):
        autocomplete = (input_tag.get("autocomplete") or "").strip().lower()
        if autocomplete not in ("off", "new-password"):
            return [CheckHit("autocomplete-enabled-password-field", page.url)]
    return []


CHECKS: dict[str, Callable[[FetchedPage], list[CheckHit]]] = {
    "missing-hsts": check_missing_hsts,
    "missing-csp": check_missing_csp,
    "missing-x-frame-options": check_missing_x_frame_options,
    "missing-x-content-type-options": check_missing_x_content_type_options,
    "missing-referrer-policy": check_missing_referrer_policy,
    "missing-permissions-policy": check_missing_permissions_policy,
    "cookie-missing-secure": check_cookie_missing_secure,
    "cookie-missing-httponly": check_cookie_missing_httponly,
    "cookie-missing-samesite": check_cookie_missing_samesite,
    "server-version-disclosure": check_server_version_disclosure,
    "verbose-error-stack-trace": check_verbose_error_stack_trace,
    "directory-listing-enabled": check_directory_listing_enabled,
    "plaintext-http": check_plaintext_http,
    "weak-tls-version": check_weak_tls_version,
    "autocomplete-enabled-password-field": check_autocomplete_enabled_password_field,
}


def run_all_checks(page: FetchedPage) -> list[CheckHit]:
    hits: list[CheckHit] = []
    for check_fn in CHECKS.values():
        hits.extend(check_fn(page))
    return hits
