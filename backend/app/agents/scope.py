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
