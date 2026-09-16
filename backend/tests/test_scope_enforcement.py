import uuid

import pytest

from app.agents.http_client import ScopedHttpClient, ScopeViolationError
from app.agents.recon import DiscoveredParameter, FormInfo
from app.agents.scope import (
    filter_forms_out_login_only,
    filter_out_login_only,
    filter_parameters_out_login_only,
    is_in_scope,
)
from app.models.project import ScopeEntry


def entry(host: str, port: int | None = None, in_scope: bool = True, purpose: str = "target") -> ScopeEntry:
    return ScopeEntry(host=host, port=port, in_scope=in_scope, purpose=purpose)


def test_matching_host_and_port_is_in_scope():
    entries = [entry("127.0.0.1", 3000)]
    assert is_in_scope("http://127.0.0.1:3000/rest/products", entries)


def test_different_port_is_out_of_scope():
    entries = [entry("127.0.0.1", 3000)]
    assert not is_in_scope("http://127.0.0.1:8080/rest/products", entries)


def test_different_host_is_out_of_scope():
    entries = [entry("127.0.0.1", 3000)]
    assert not is_in_scope("http://evil.example.test:3000/", entries)


def test_null_port_entry_matches_any_port():
    entries = [entry("app.example.test", None)]
    assert is_in_scope("https://app.example.test/", entries)
    assert is_in_scope("https://app.example.test:8443/", entries)


def test_https_default_port_443_matched_without_explicit_port_in_url():
    entries = [entry("app.example.test", 443)]
    assert is_in_scope("https://app.example.test/", entries)


def test_explicit_out_of_scope_entry_overrides_broader_allow():
    entries = [entry("app.example.test", None, in_scope=True), entry("app.example.test", 9999, in_scope=False)]
    assert is_in_scope("https://app.example.test/", entries)
    assert not is_in_scope("https://app.example.test:9999/", entries)


def test_no_matching_entry_is_out_of_scope():
    assert not is_in_scope("https://anything.test/", [])


async def test_scoped_client_raises_before_any_request_for_out_of_scope_url():
    client = ScopedHttpClient(
        version_id=uuid.uuid4(), scope_entries=[entry("allowed.test")], db_session=None
    )
    with pytest.raises(ScopeViolationError):
        await client.get("https://not-allowed.test/")
    await client.aclose()


def test_login_only_host_is_excluded_from_fuzzable_endpoints():
    entries = [entry("app.example.test"), entry("idp.okta.com", purpose="login_only")]
    urls = ["https://app.example.test/dashboard", "https://idp.okta.com/account-settings"]

    assert filter_out_login_only(urls, entries) == ["https://app.example.test/dashboard"]


def test_login_only_host_is_excluded_from_fuzzable_forms():
    entries = [entry("app.example.test"), entry("idp.okta.com", purpose="login_only")]
    real_form = FormInfo(action_url="https://app.example.test/comments", method="POST", fields=[])
    idp_form = FormInfo(action_url="https://idp.okta.com/mfa-settings", method="POST", fields=[])

    assert filter_forms_out_login_only([real_form, idp_form], entries) == [real_form]


def test_login_only_host_is_excluded_from_fuzzable_parameters():
    entries = [entry("app.example.test"), entry("idp.okta.com", purpose="login_only")]
    real_param = DiscoveredParameter(url="https://app.example.test/search?q=1", method="GET", name="q")
    idp_param = DiscoveredParameter(url="https://idp.okta.com/authorize?state=1", method="GET", name="state")

    assert filter_parameters_out_login_only([real_param, idp_param], entries) == [real_param]


def test_target_derived_entry_is_never_filtered():
    # purpose defaults to "target" for a real, analyst-added Target —
    # only an explicit login_only tag ever excludes a host.
    entries = [entry("app.example.test")]
    urls = ["https://app.example.test/dashboard"]

    assert filter_out_login_only(urls, entries) == urls
