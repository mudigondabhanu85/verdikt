import uuid

from app.agents.sandbox_client import derive_allow_list
from app.models.project import ScopeEntry


def _scope_entry(**overrides) -> ScopeEntry:
    defaults = dict(version_id=uuid.uuid4(), host="localhost", port=80, in_scope=True, purpose="target")
    defaults.update(overrides)
    return ScopeEntry(**defaults)


def test_derive_allow_list_resolves_a_real_host():
    entries = derive_allow_list([_scope_entry(host="localhost", port=8080)])
    assert len(entries) == 1
    assert entries[0].host == "localhost"
    assert entries[0].ip in ("127.0.0.1", "::1")
    assert entries[0].port == 8080


def test_derive_allow_list_excludes_out_of_scope_entries():
    entries = derive_allow_list([_scope_entry(in_scope=False)])
    assert entries == []


def test_derive_allow_list_excludes_login_only_hosts():
    """A purpose="login_only" host (e.g. a third-party IdP — see
    app.api.routes.credentials._ensure_login_endpoint_in_scope) is real,
    technical in-scope access for login purposes only and must never
    become a pentest target — same distinction
    app.agents.scope.filter_out_login_only already enforces for the
    existing crawl-derived surface."""
    entries = derive_allow_list([_scope_entry(purpose="login_only")])
    assert entries == []


def test_derive_allow_list_skips_unresolvable_hosts_without_failing():
    entries = derive_allow_list(
        [_scope_entry(host="this-host-does-not-resolve.invalid"), _scope_entry(host="localhost")]
    )
    assert len(entries) == 1
    assert entries[0].host == "localhost"


def test_derive_allow_list_preserves_null_port():
    """None means "every port on this host is in scope" — mirrors
    app.agents.scope.is_in_scope's own null-port handling exactly, must
    not silently default to {80, 443}."""
    entries = derive_allow_list([_scope_entry(port=None)])
    assert entries[0].port is None


def test_allow_list_entry_to_dict_round_trips():
    entries = derive_allow_list([_scope_entry(host="localhost", port=443)])
    d = entries[0].to_dict()
    assert d == {"host": "localhost", "ip": entries[0].ip, "port": 443, "protocol": "tcp"}
