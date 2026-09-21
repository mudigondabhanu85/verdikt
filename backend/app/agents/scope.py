from urllib.parse import urlsplit

from app.models.project import ScopeEntry


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def is_in_scope(url: str, scope_entries: list[ScopeEntry]) -> bool:
    """The actual technical allow-list enforcement §1.1 calls for — agents
    must never be able to reach a host outside a Version's scope, no
    matter what a crawl or a check turns up. Deny wins on ambiguity: if a
    host:port matches both an in_scope and an explicitly out-of-scope
    entry, it's treated as out of scope.
    """
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    port = parsed.port or _default_port(parsed.scheme)

    def matches(entry: ScopeEntry) -> bool:
        return entry.host.lower() == host and (entry.port is None or entry.port == port)

    allowed = any(matches(e) for e in scope_entries if e.in_scope)
    denied = any(matches(e) for e in scope_entries if not e.in_scope)
    return allowed and not denied


def _is_login_only_host(host: str, scope_entries: list[ScopeEntry]) -> bool:
    host = host.lower()
    return any(e.host.lower() == host and e.purpose == "login_only" for e in scope_entries)


def filter_out_login_only(urls: list[str], scope_entries: list[ScopeEntry]) -> list[str]:
    """Drops any URL whose host is scoped purpose="login_only" (see
    app.api.routes.credentials._ensure_login_endpoint_in_scope) — a host
    added purely so a login POST could reach it (very often a
    third-party IdP like Okta/Auth0) is real, technical in-scope access
    for login purposes, but was never authorization to send it
    injection/XSS/SSTI payloads. Applied at every point
    discovered_endpoints/forms/parameters get produced (app.agents.graph)
    rather than per-agent, so no detection agent — old or new — has to
    remember to check this itself to stay safe.
    """
    return [u for u in urls if not _is_login_only_host(urlsplit(u).hostname or "", scope_entries)]


def filter_forms_out_login_only(forms: list, scope_entries: list[ScopeEntry]) -> list:
    """Same filter as filter_out_login_only, keyed by each form's own
    action_url — a <form> recon happened to find on a login-only host
    (an IdP's own account-settings page, say) must never become a
    fuzzing target either.
    """
    return [f for f in forms if not _is_login_only_host(urlsplit(f.action_url).hostname or "", scope_entries)]


def filter_parameters_out_login_only(parameters: list, scope_entries: list[ScopeEntry]) -> list:
    """Same filter as filter_out_login_only, keyed by each parameter's
    own url.
    """
    return [p for p in parameters if not _is_login_only_host(urlsplit(p.url).hostname or "", scope_entries)]


def filter_json_bodies_out_login_only(bodies: list, scope_entries: list[ScopeEntry]) -> list:
    """Same filter as filter_out_login_only, keyed by each
    DiscoveredJsonBody's own url.
    """
    return [b for b in bodies if not _is_login_only_host(urlsplit(b.url).hostname or "", scope_entries)]
