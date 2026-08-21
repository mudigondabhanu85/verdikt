import time
import uuid

import pytest

from app.auth.oidc import (
    OidcError,
    build_authorization_url,
    decode_state,
    encode_state,
    exchange_code_for_id_token,
    fetch_discovery_document,
    verify_id_token,
)
from app.models.oidc_provider_config import OidcProviderConfig
from app.vault.credential_vault import encrypt_secret
from tests.oidc_fixture_idp import FixtureIdp


@pytest.fixture
def idp():
    fixture = FixtureIdp()
    yield fixture
    fixture.shutdown()


def _config_for(idp: FixtureIdp, **overrides) -> OidcProviderConfig:
    defaults = dict(
        org_id=uuid.uuid4(),
        label="Test IdP",
        issuer=idp.base_url,
        client_id="verdikt-client",
        encrypted_client_secret=encrypt_secret("super-secret-client-value"),
        redirect_uri="https://verdikt.example/auth/oidc/callback",
        default_role="viewer",
    )
    defaults.update(overrides)
    return OidcProviderConfig(**defaults)


async def test_fetch_discovery_document_real_http(idp):
    discovery = await fetch_discovery_document(idp.base_url)
    assert discovery.token_endpoint == f"{idp.base_url}/token"
    assert discovery.jwks_uri == f"{idp.base_url}/jwks"


async def test_fetch_discovery_document_rejects_unreachable_issuer():
    with pytest.raises(OidcError):
        await fetch_discovery_document("http://127.0.0.1:1")


def test_state_round_trips_and_carries_config_id():
    config_id = uuid.uuid4()
    state = encode_state(config_id)
    assert decode_state(state) == config_id


def test_decode_state_rejects_garbage():
    with pytest.raises(OidcError):
        decode_state("not-a-real-jwt")


def test_build_authorization_url_includes_required_params(idp):
    config = _config_for(idp)
    discovery_endpoint = f"{idp.base_url}/authorize"

    class _Discovery:
        authorization_endpoint = discovery_endpoint

    url = build_authorization_url(_Discovery(), config, "the-state")
    assert url.startswith(discovery_endpoint + "?")
    assert "client_id=verdikt-client" in url
    assert "state=the-state" in url
    assert "response_type=code" in url


async def test_full_code_exchange_and_id_token_verification_real_rsa_signature(idp):
    config = _config_for(idp)
    discovery = await fetch_discovery_document(idp.base_url)

    now = int(time.time())
    code = idp.issue_code(
        {
            "iss": idp.base_url,
            "aud": config.client_id,
            "sub": "user-subject-123",
            "email": "alice@example.test",
            "iat": now,
            "exp": now + 300,
        }
    )

    id_token = await exchange_code_for_id_token(discovery, config, code)
    identity = verify_id_token(id_token, discovery, config)

    assert identity.subject == "user-subject-123"
    assert identity.email == "alice@example.test"


async def test_exchange_rejects_unknown_code(idp):
    config = _config_for(idp)
    discovery = await fetch_discovery_document(idp.base_url)

    with pytest.raises(OidcError):
        await exchange_code_for_id_token(discovery, config, "not-a-real-code")


async def test_verify_id_token_rejects_wrong_audience(idp):
    config = _config_for(idp)
    discovery = await fetch_discovery_document(idp.base_url)

    now = int(time.time())
    code = idp.issue_code(
        {
            "iss": idp.base_url,
            "aud": "some-other-client",  # not config.client_id
            "sub": "user-subject-123",
            "email": "alice@example.test",
            "iat": now,
            "exp": now + 300,
        }
    )
    id_token = await exchange_code_for_id_token(discovery, config, code)

    with pytest.raises(OidcError):
        verify_id_token(id_token, discovery, config)


async def test_verify_id_token_rejects_expired_token(idp):
    config = _config_for(idp)
    discovery = await fetch_discovery_document(idp.base_url)

    now = int(time.time())
    code = idp.issue_code(
        {
            "iss": idp.base_url,
            "aud": config.client_id,
            "sub": "user-subject-123",
            "email": "alice@example.test",
            "iat": now - 1000,
            "exp": now - 500,  # already expired
        }
    )
    id_token = await exchange_code_for_id_token(discovery, config, code)

    with pytest.raises(OidcError):
        verify_id_token(id_token, discovery, config)
