"""Shared parameter-probing plumbing used by both the Injection and XSS
agents: turning discovered query params / form fields / JSON request
bodies into a uniform ProbeTarget, and substituting one parameter's
value to fetch a response.
"""

import json
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

import httpx

from app.agents.http_client import AuthenticatedSession, ScopedHttpClient
from app.agents.recon import DiscoveredJsonBody, DiscoveredParameter, FormInfo

BASELINE_VALUE = "verdikt1"


@dataclass
class ProbeTarget:
    url: str
    method: str
    param_name: str
    other_fields: dict[str, str] = field(default_factory=dict)
    # "application/x-www-form-urlencoded" (the default, matching every
    # HTML <form> DVWA/most server-rendered apps ever submit) or
    # "application/json" (a SPA's real API body shape — see
    # json_body_probe_targets). Meaningless for GET, which has no body.
    content_type: str = "application/x-www-form-urlencoded"


def query_probe_targets(parameters: list[DiscoveredParameter]) -> list[ProbeTarget]:
    return [
        ProbeTarget(url=p.url, method="GET", param_name=p.name)
        for p in parameters
        if p.method == "GET"
    ]


def form_probe_targets(forms: list[FormInfo]) -> list[ProbeTarget]:
    targets = []
    for form in forms:
        testable = [f for f in form.fields if f.type not in ("hidden", "submit", "button")]
        for f in testable:
            # Real, live-found bug against DVWA: giving every companion
            # field the exact same literal BASELINE_VALUE means any form
            # gated by an equality check between two of its own fields
            # (a password-change form's "new" vs. "confirm", for
            # instance) silently accepts the very first *baseline* fetch
            # — sent before any actual attack payload is even tried — as
            # a genuinine, matching submission. DVWA's own CSRF page is
            # exactly this shape (password_new/password_conf, no
            # current-password check at low security), and its real
            # admin password got changed to "verdikt1" purely as a side
            # effect of routine SQLi/XSS probing, not any deliberate
            # password-change test. Suffixing each companion field's
            # value with its own name keeps every value non-empty,
            # traceably Verdikt-sourced, and — critically — never
            # coincidentally equal to another field's value, so a
            # same-form equality gate can no longer be satisfied by
            # accident.
            others = {o.name: f"{BASELINE_VALUE}_{o.name}" for o in form.fields if o.name != f.name}
            targets.append(
                ProbeTarget(url=form.action_url, method=form.method, param_name=f.name, other_fields=others)
            )
    return targets


def json_body_probe_targets(bodies: list[DiscoveredJsonBody]) -> list[ProbeTarget]:
    """A client-rendered SPA's real vulnerable surface (Juice Shop's
    product search, login, basket, profile-update endpoints) is
    overwhelmingly a JSON request body, never a server-rendered <form>
    — form_probe_targets structurally cannot see any of it. Same
    per-field-distinct-baseline-value discipline as form_probe_targets,
    for the same reason: a field like "password"/"passwordRepeat" would
    otherwise be vulnerable to the exact same accidental-match hazard.
    """
    targets = []
    for body in bodies:
        for name in body.fields:
            others = {o: f"{BASELINE_VALUE}_{o}" for o in body.fields if o != name}
            targets.append(
                ProbeTarget(
                    url=body.url,
                    method=body.method,
                    param_name=name,
                    other_fields=others,
                    content_type="application/json",
                )
            )
    return targets


def build_request(target: ProbeTarget, value: str) -> tuple[str, str | None, str | None]:
    if target.method == "GET":
        parsed = urlsplit(target.url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        # Real, live-found bug against DVWA: a multi-field GET form (e.g.
        # SQL Injection's "id" + "Submit") needs every companion field
        # present for the target's own server-side logic to actually run
        # (DVWA's low.php gates its query behind `isset($_GET['Submit'])`)
        # — omitting other_fields here (unlike the POST branch below,
        # which already includes them) silently degraded every such
        # probe into fetching the untouched "enter a value" placeholder
        # page instead of ever submitting the form, with no error and no
        # visible symptom beyond a quietly-empty finding list.
        for name, other_value in target.other_fields.items():
            params[name] = [other_value]
        params[target.param_name] = [value]
        new_query = urlencode({k: v[0] for k, v in params.items()})
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, "")), None, None

    body_fields = dict(target.other_fields)
    body_fields[target.param_name] = value
    if target.content_type == "application/json":
        return target.url, json.dumps(body_fields), "application/json"
    return target.url, urlencode(body_fields), "application/x-www-form-urlencoded"


async def fetch_with_value(
    client: ScopedHttpClient,
    target: ProbeTarget,
    value: str,
    session: AuthenticatedSession | None = None,
) -> httpx.Response:
    url, body, content_type = build_request(target, value)
    if body is None:
        return await client.get(url, session=session)
    return await client.post(url, body=body, content_type=content_type, session=session)
