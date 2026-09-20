import json
import uuid
from urllib.parse import urlencode

import httpx
from bs4 import BeautifulSoup
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.http_client import AuthenticatedSession, ScopedHttpClient
from app.agents.macro import MacroPlayer, MacroStep
from app.agents.recon import FormInfo
from app.models.credential import CredentialSet
from app.models.login_macro import LoginMacro
from app.vault.credential_vault import decrypt_credential

_DEFAULT_JSON_BODY_TEMPLATE = '{"username": "{username}", "password": "{password}"}'


def pick_best_session(
    sessions: dict[uuid.UUID, AuthenticatedSession] | None,
) -> AuthenticatedSession | None:
    """Every call site that only needs "one representative identity" (a
    site-shape-discovery crawl, a browser-proof check, anything that
    isn't Access Control's genuine per-credential juggling) used to just
    grab `next(iter(sessions.values()))` — whichever credential happened
    to be inserted into the dict first, with no regard for whether that
    session actually works. That's a real, live-found flakiness source:
    MacroPlayer.replay() (app.agents.macro) returns whatever cookies
    happen to exist in the browser context at the end of a recording
    replay, even when the recording didn't actually reach an
    authenticated state — a stray CSRF/analytics cookie set on the login
    page itself is enough to make `if not cookies: return None` pass
    without the session being real. If even one credential in a
    multi-credential Version hits that path, picking "whichever's first"
    means a scan can silently run its single-representative-identity
    checks against a broken session instead of a working one, depending
    entirely on dict insertion order — a login.py-internal implementation
    detail no caller should have to know or care about.

    Prefers a bearer token (the least ambiguous auth signal — either
    it's set to something or it isn't) over cookies, and among
    cookie-based sessions, the one with the most cookies — a real login
    routinely sets several (session id, CSRF token, remember-me, ...),
    while a flaky macro replay's leftover is typically just one. Ties
    (including "every session looks equally good") resolve to whichever
    came first, same as today — this changes nothing for the common
    single-credential case.
    """
    if not sessions:
        return None
    return max(sessions.values(), key=lambda s: (1 if s.bearer_token else 0, len(s.cookies)))

# Recognizable third-party IdP signatures (§5) — deliberately narrow:
# a false positive here means skipping a legitimate simple form-login
# unnecessarily, so this stays to genuinely IdP-specific hosts/paths,
# never generic words like "login" or "auth" that a normal app's own
# login form could plausibly use itself.
_SSO_REDIRECT_MARKERS = (
    "okta.com",
    "oktapreview.com",
    "login.microsoftonline.com",
    "auth0.com",
    "onelogin.com",
    "pingidentity.com",
    "/saml",
    "/sso/",
    "oauth2/authorize",
    "/oauth2/v1/authorize",
)


def _looks_like_sso_redirect(url: str) -> bool:
    """Classifies a login form's action URL as pointing at a third-party
    identity provider rather than the target application's own login
    handler (§5). When true, SessionManager must not blindly POST
    credentials into an unfamiliar IdP login page it knows nothing
    about — it falls back to requiring a recorded login macro instead,
    same as when no form is found at all.
    """
    lowered = url.lower()
    return any(marker in lowered for marker in _SSO_REDIRECT_MARKERS)


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


def _live_field_values(html: str, field_names: set[str]) -> dict[str, str]:
    """Real current values for named `<input>` fields — hidden CSRF
    tokens and submit-button fields alike — read from a freshly-fetched
    copy of the login page, not a stale/empty placeholder. Two distinct
    real failures found live against DVWA's login.php: (1) it genuinely
    rejects a login whose `user_token` doesn't match the one minted for
    the exact session the POST rides on, so sending it blank isn't a
    graceful fallback, it's a login that always fails silently; (2) its
    submit button (`<input type="submit" name="Login" value="Login">`)
    is itself a named field the server checks via `isset($_POST['Login'])`
    to know the form was submitted at all — omitting it (as this code
    used to, since only type=="hidden" fields were ever filled in) means
    the handler never even attempts the login, also failing silently
    with a plain 200 back to the same page. Best-effort: a field that
    isn't present (or is itself blank) on the fetched page is omitted.
    """
    if not field_names:
        return {}
    soup = BeautifulSoup(html, "html.parser")
    values: dict[str, str] = {}
    for input_tag in soup.find_all("input"):
        name = input_tag.get("name")
        if name in field_names:
            value = input_tag.get("value")
            if value:
                values[name] = value
    return values


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
        return await self.login_with_credentials(credential_set, forms, username=username, secret=secret)

    async def login_with_credentials(
        self, credential_set: CredentialSet, forms: list[FormInfo], *, username: str, secret: str
    ) -> AuthenticatedSession | None:
        """Same three-strategy dispatch as login(), but against an
        explicit (username, secret) pair instead of the CredentialSet's
        own stored/encrypted one. Exists for app.agents.weak_password_policy,
        which needs to attempt a real login with a password that is *not*
        what's on file (a throwaway one-character password while probing,
        then the original again while reverting) — reusing this instead of
        hand-rolling a second copy of the form/explicit-login branching
        below is the same "don't reimplement, consolidate" call this
        codebase makes wherever request-building logic would otherwise
        need to stay in sync across two independent copies.
        """
        if credential_set.credential_type == "api_token":
            # A pre-issued bearer token/API key (e.g. for an imported
            # OpenAPI/Postman collection with no login flow at all) —
            # `secret` holds the token directly, applied statically to
            # every request via ScopedHttpClient's existing
            # AuthenticatedSession.bearer_token mechanism (same header
            # injection every other credential type already gets, just
            # skipping the login POST/form/macro dance entirely since
            # there's nothing to log into).
            session = AuthenticatedSession(credential_set_id=credential_set.id, bearer_token=secret)
            if credential_set.extra_cookies:
                session.cookies = dict(credential_set.extra_cookies)
            if credential_set.extra_headers:
                session.extra_headers = dict(credential_set.extra_headers)
            return session

        # See ScopedHttpClient.reset_cookie_jar's docstring — a fresh
        # slate before every login attempt, since whatever the recon
        # crawl (or an earlier credential's login attempt) happened to
        # accumulate must never bleed into this one.
        self._client.reset_cookie_jar()

        if credential_set.login_endpoint:
            return await self._login_explicit(credential_set, username, secret)

        form = _find_login_form(forms)
        if form is not None and not _looks_like_sso_redirect(form.action_url):
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
        if session is not None and credential_set.extra_headers:
            session.extra_headers = {**session.extra_headers, **credential_set.extra_headers}
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
        # username_field is allowed to be absent — a real, common gate
        # shape (e.g. Shopify's storefront password-protection page) is a
        # single shared secret with no per-user identity at all: just a
        # password field plus a CSRF token. password_field is still
        # mandatory, since that's what makes this a login form in the
        # first place (see _find_login_form).
        username_field = _guess_username_field(form)
        password_field = _guess_password_field(form)
        if not password_field:
            return None

        # ScopedHttpClient never relies on an implicit cookie jar for
        # anonymous (session=None) requests — every identity's cookies
        # are threaded through explicitly, precisely so concurrent
        # identities never leak into a shared jar (see _request's own
        # comment). That means the pre-login page-view that set the
        # server-side session this form's submission needs to belong to
        # is never captured on its own. Real, observed failure: DVWA
        # (and presumably other apps) issue a fresh PHPSESSID on every
        # unauthenticated page view — recon's own crawl already
        # accumulated several different ones for this same login page,
        # so blindly POSTing with no cookie at all attaches the login
        # attempt to no session, and it silently fails (200 back to the
        # login page, not a redirect/new session). A fresh GET of the
        # form's own page immediately before POSTing captures exactly
        # the one session cookie this specific submission is entitled
        # to, with no ambiguity from any earlier crawl requests. The
        # same fetch also captures each hidden/submit field's real
        # current value (see _live_field_values) — DVWA's login.php was
        # found live to genuinely reject a mismatched/blank CSRF token,
        # and separately to never even attempt a login whose submit
        # button field was omitted.
        pre_login = await self._client.get(form.action_url)
        pre_login_cookies = _cookies_from_response(pre_login)

        payload = {password_field: secret}
        if username_field:
            payload[username_field] = username
        # Every other field on the form — hidden CSRF tokens and the
        # submit button alike — gets its real, current value from the
        # fresh pre_login fetch rather than a blank placeholder (see
        # _live_field_values's docstring for why both matter).
        other_names = {f.name for f in form.fields if f.type in ("hidden", "submit") and f.name not in payload}
        live_values = _live_field_values(pre_login.text, other_names)
        for name in other_names:
            payload[name] = live_values.get(name, "")

        response = await self._client.post(
            form.action_url,
            body=urlencode(payload),
            content_type="application/x-www-form-urlencoded",
            extra_headers=(
                {"Cookie": "; ".join(f"{k}={v}" for k, v in pre_login_cookies.items())}
                if pre_login_cookies
                else None
            ),
        )
        return self._session_from_response(
            credential_set, response, None, fallback_cookies=pre_login_cookies
        )

    def _session_from_response(
        self,
        credential_set: CredentialSet,
        response: httpx.Response,
        token_path: str | None,
        *,
        fallback_cookies: dict[str, str] | None = None,
    ) -> AuthenticatedSession | None:
        # fallback_cookies covers the common case where a login POST's
        # own response sets no *new* Set-Cookie at all — the session ID
        # a pre-login page view already established simply persists
        # unchanged through login (only its server-side state flips to
        # authenticated), so the response itself looks cookie-less even
        # though the login genuinely succeeded. Real cookies from this
        # response still win on key collision (some apps do rotate the
        # session ID on login, e.g. session-fixation hardening).
        cookies = {**(fallback_cookies or {}), **_cookies_from_response(response)}
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
            credential_set_id=credential_set.id,
            cookies=cookies,
            bearer_token=bearer_token,
            extra_headers=dict(credential_set.extra_headers) if credential_set.extra_headers else {},
        )
