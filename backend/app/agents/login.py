import json
from urllib.parse import urlencode

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.http_client import AuthenticatedSession, ScopedHttpClient
from app.agents.macro import MacroPlayer, MacroStep
from app.agents.recon import FormInfo
from app.models.credential import CredentialSet
from app.models.login_macro import LoginMacro
from app.vault.credential_vault import decrypt_credential

_DEFAULT_JSON_BODY_TEMPLATE = '{"username": "{username}", "password": "{password}"}'


def _fill_template(template: str, username: str, secret: str) -> str:
    """Plain substring substitution, not str.format() — a JSON template's
    own literal braces (every JSON object) would otherwise collide with
    format-string syntax, forcing callers to double-escape every brace in
    their template just to name two placeholders. json.dumps(...)[1:-1]
    JSON-escapes the values (quotes, backslashes, etc.) before splicing
    them into the template so the result stays valid JSON.
    """
    return template.replace("{username}", json.dumps(username)[1:-1]).replace(
        "{password}", json.dumps(secret)[1:-1]
    )


def _get_dotted(data: object, path: str) -> object | None:
    node = data
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _find_login_form(forms: list[FormInfo]) -> FormInfo | None:
    for form in forms:
        if any(field.type == "password" for field in form.fields):
            return form
    return None


def _guess_password_field(form: FormInfo) -> str | None:
    for f in form.fields:
        if f.type == "password":
            return f.name
    return None


def _guess_username_field(form: FormInfo) -> str | None:
    candidates = [f for f in form.fields if f.type in ("text", "email") and f.name]
    for f in candidates:
        lowered = f.name.lower()
        if any(marker in lowered for marker in ("user", "email", "login")):
            return f.name
    return candidates[0].name if candidates else None


def _cookies_from_response(response: httpx.Response) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for raw in response.headers.get_list("set-cookie"):
        name, _, rest = raw.partition("=")
        value = rest.split(";", 1)[0]
        if name.strip():
            cookies[name.strip()] = value.strip()
    return cookies


def _bearer_token_from_response(response: httpx.Response, token_path: str | None) -> str | None:
    if not token_path:
        return None
    try:
        data = json.loads(response.text)
    except json.JSONDecodeError:
        return None
    token = _get_dotted(data, token_path)
    return token if isinstance(token, str) else None


class SessionManager:
    """Tries three session-establishment strategies in order (§4/§5):
    1. Explicit CredentialSet login config (needed for JSON/REST SPA
       logins auto-discovery can't find).
    2. Auto-discovering a classic server-rendered <form> with a password
       field from recon'd pages.
    3. Replaying a recorded Playwright login macro (app.agents.macro) —
       covers logins that are neither a plain JSON endpoint nor a simple
       <form> (client-side validation, multi-step flows, manual-OTP
       flows recorded once by an analyst). Only tried when a db_session
       is supplied, since it needs to look up a LoginMacro row.
    """

    def __init__(self, client: ScopedHttpClient, db_session: AsyncSession | None = None):
        self._client = client
        self._db_session = db_session

    async def login(
        self, credential_set: CredentialSet, forms: list[FormInfo]
    ) -> AuthenticatedSession | None:
        username, secret = decrypt_credential(credential_set.encrypted_secret)

        if credential_set.login_endpoint:
            return await self._login_explicit(credential_set, username, secret)

        form = _find_login_form(forms)
        if form is not None:
            session = await self._login_via_form(credential_set, form, username, secret)
            if session is not None:
                return session

        if self._db_session is not None:
            return await self._login_via_macro(credential_set, username, secret)

        return None

    async def _login_via_macro(
        self, credential_set: CredentialSet, username: str, secret: str
    ) -> AuthenticatedSession | None:
        assert self._db_session is not None
        result = await self._db_session.execute(
            select(LoginMacro)
            .where(LoginMacro.credential_set_id == credential_set.id)
            .order_by(LoginMacro.created_at.desc())
            .limit(1)
        )
        macro = result.scalar_one_or_none()
        if macro is None:
            return None

        steps = [MacroStep.from_dict(raw) for raw in macro.steps]
        player = MacroPlayer()
        session = await player.replay(
            steps,
            credential_set_id=credential_set.id,
            username=username,
            password=secret,
            headless=True,
        )
        if session is not None and credential_set.extra_cookies:
            # extra_cookies wins on key collision — see _session_from_response.
            session.cookies = {**session.cookies, **credential_set.extra_cookies}
        return session

    async def _login_explicit(
        self, credential_set: CredentialSet, username: str, secret: str
    ) -> AuthenticatedSession | None:
        template = credential_set.login_body_template or _DEFAULT_JSON_BODY_TEMPLATE
        body = _fill_template(template, username, secret)
        content_type = credential_set.login_content_type or "application/json"
        method = (credential_set.login_method or "POST").upper()

        response = await self._client.post(
            credential_set.login_endpoint, body=body, content_type=content_type
        ) if method == "POST" else await self._client.get(credential_set.login_endpoint)

        return self._session_from_response(
            credential_set, response, credential_set.token_response_path
        )

    async def _login_via_form(
        self, credential_set: CredentialSet, form: FormInfo, username: str, secret: str
    ) -> AuthenticatedSession | None:
        username_field = _guess_username_field(form)
        password_field = _guess_password_field(form)
        if not username_field or not password_field:
            return None

        payload = {username_field: username, password_field: secret}
        for f in form.fields:
            if f.type == "hidden" and f.name not in payload:
                # Best-effort only — we don't re-fetch to capture a fresh
                # CSRF token value, so hidden fields are sent empty. Forms
                # requiring a live CSRF token will fail login here and
                # SessionManager returns None, same as any other login
                # failure; explicit login config is the reliable path for
                # CSRF-protected forms.
                payload[f.name] = ""

        response = await self._client.post(
            form.action_url,
            body=urlencode(payload),
            content_type="application/x-www-form-urlencoded",
        )
        return self._session_from_response(credential_set, response, None)

    def _session_from_response(
        self, credential_set: CredentialSet, response: httpx.Response, token_path: str | None
    ) -> AuthenticatedSession | None:
        cookies = _cookies_from_response(response)
        bearer_token = _bearer_token_from_response(response, token_path)

        if not cookies and not bearer_token:
            return None

        if credential_set.extra_cookies:
            # extra_cookies wins on key collision — the whole point of a
            # fixed static cookie is to force a specific value regardless
            # of whatever the target's own login response might set. A
            # real target found live: DVWA's login response itself resets
            # a `security` cookie to its own default on every login,
            # which would otherwise silently override the very setting
            # extra_cookies exists to pin.
            cookies = {**cookies, **credential_set.extra_cookies}

        return AuthenticatedSession(
            credential_set_id=credential_set.id, cookies=cookies, bearer_token=bearer_token
        )
