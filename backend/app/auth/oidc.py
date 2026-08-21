"""Generic OIDC Authorization Code flow (§9 enterprise hardening) — works
with any standard-compliant identity provider (Okta, Azure AD, Google
Workspace, Auth0, ...) via OIDC discovery + JWKS, not a provider-specific
SDK. Application code only ever talks to this module, never an IdP's
proprietary API.

Flow:
1. GET /auth/oidc/{config_id}/login -> fetch_discovery_document, build a
   signed `state` (encode_state — no server-side session storage needed),
   redirect the browser to the IdP's authorization_endpoint.
2. IdP redirects back to GET /auth/oidc/callback?code=...&state=....
   decode_state recovers which OidcProviderConfig this belongs to;
   exchange_code_for_id_token trades the code for an ID token;
   verify_id_token validates its signature (via the IdP's JWKS), issuer,
   and audience before any claim in it is trusted.
"""

import secrets
import time
import uuid
from dataclasses import dataclass
from urllib.parse import urlencode

import httpx
import jwt

from app.config import get_settings
from app.models.oidc_provider_config import OidcProviderConfig
from app.vault.credential_vault import decrypt_secret

_STATE_TTL_SECONDS = 600


class OidcError(RuntimeError):
    pass


@dataclass
class OidcDiscoveryDocument:
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str


@dataclass
class OidcIdentity:
    subject: str
    email: str | None


async def fetch_discovery_document(
    issuer: str, *, transport: httpx.AsyncBaseTransport | None = None
) -> OidcDiscoveryDocument:
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    try:
        async with httpx.AsyncClient(transport=transport, timeout=10.0) as client:
            response = await client.get(url)
    except httpx.HTTPError as exc:
        raise OidcError(f"Could not reach OIDC issuer {issuer!r}: {exc}") from exc
    if response.status_code != 200:
        raise OidcError(f"OIDC discovery failed for issuer {issuer!r}: {response.status_code}")
    doc = response.json()
    try:
        return OidcDiscoveryDocument(
            authorization_endpoint=doc["authorization_endpoint"],
            token_endpoint=doc["token_endpoint"],
            jwks_uri=doc["jwks_uri"],
        )
    except KeyError as exc:
        raise OidcError(f"OIDC discovery document for {issuer!r} is missing {exc}") from exc


def encode_state(config_id: uuid.UUID) -> str:
    """A signed, self-contained state param — no server-side session
    storage needed. Carries which OidcProviderConfig initiated the flow
    plus a nonce (CSRF protection: a forged callback can't produce a
    validly-signed state without knowing settings.jwt_secret) and a short
    expiry.
    """
    settings = get_settings()
    payload = {
        "config_id": str(config_id),
        "nonce": secrets.token_urlsafe(16),
        "exp": int(time.time()) + _STATE_TTL_SECONDS,
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_state(state: str) -> uuid.UUID:
    settings = get_settings()
    try:
        payload = jwt.decode(state, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
        return uuid.UUID(payload["config_id"])
    except jwt.InvalidTokenError as exc:
        raise OidcError(f"Invalid or expired OIDC state: {exc}") from exc


def build_authorization_url(
    discovery: OidcDiscoveryDocument, config: OidcProviderConfig, state: str
) -> str:
    params = {
        "response_type": "code",
        "client_id": config.client_id,
        "redirect_uri": config.redirect_uri,
        "scope": "openid email profile",
        "state": state,
    }
    return f"{discovery.authorization_endpoint}?{urlencode(params)}"


async def exchange_code_for_id_token(
    discovery: OidcDiscoveryDocument,
    config: OidcProviderConfig,
    code: str,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> str:
    client_secret = decrypt_secret(config.encrypted_client_secret)
    try:
        async with httpx.AsyncClient(transport=transport, timeout=10.0) as client:
            response = await client.post(
                discovery.token_endpoint,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": config.redirect_uri,
                    "client_id": config.client_id,
                    "client_secret": client_secret,
                },
            )
    except httpx.HTTPError as exc:
        raise OidcError(f"Could not reach OIDC token endpoint: {exc}") from exc
    if response.status_code != 200:
        raise OidcError(f"OIDC token exchange failed: {response.status_code} {response.text}")
    body = response.json()
    id_token = body.get("id_token")
    if not id_token:
        raise OidcError("OIDC token response did not include an id_token")
    return id_token


def verify_id_token(
    id_token: str,
    discovery: OidcDiscoveryDocument,
    config: OidcProviderConfig,
    *,
    jwks_client: "jwt.PyJWKClient | None" = None,
) -> OidcIdentity:
    """Validates the ID token's signature against the IdP's published
    JWKS, plus issuer and audience — nothing in the token is trusted
    before this passes. jwks_client is test-only plumbing (a
    PyJWKClient pointed at a local fixture JWKS endpoint instead of a
    real IdP's).
    """
    client = jwks_client or jwt.PyJWKClient(discovery.jwks_uri)
    try:
        signing_key = client.get_signing_key_from_jwt(id_token)
        claims = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256"],
            audience=config.client_id,
            issuer=config.issuer,
        )
    except jwt.InvalidTokenError as exc:
        raise OidcError(f"ID token validation failed: {exc}") from exc

    subject = claims.get("sub")
    if not subject:
        raise OidcError("ID token is missing the required 'sub' claim")
    return OidcIdentity(subject=subject, email=claims.get("email"))
