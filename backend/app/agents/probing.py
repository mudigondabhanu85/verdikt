"""Shared parameter-probing plumbing used by both the Injection and XSS
agents: turning discovered query params / form fields / JSON request
bodies / REST-style path segments into a uniform ProbeTarget, and
substituting one parameter's value to fetch a response.
"""

import json
from dataclasses import dataclass, field
from urllib.parse import parse_qs, quote, urlencode, urlsplit, urlunsplit

import httpx

from app.agents.http_client import AuthenticatedSession, ScopedHttpClient
from app.agents.idor import find_numeric_id_segment, substitute_path_segment
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
    # Set only by path_segment_probe_targets — when present, the
    # injection point is a position in target.url's own path (e.g. the
    # "3" in /rest/products/3/reviews), not a query/body field at all.
    # Takes priority over every other field in build_request below.
    path_segment_index: int | None = None


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


def _path_segment_label(url: str, index: int) -> str:
    segments = urlsplit(url).path.split("/")
    # The segment right before the id usually names the resource it
    # identifies (".../products/3" -> "products") — a much more useful
    # label in a Finding's "parameter 'X'" phrasing than a bare index.
    if index > 0 and segments[index - 1]:
        return f"{segments[index - 1]}_id (path segment)"
    return f"path segment {index}"


def path_segment_probe_targets(endpoints: list[str]) -> list[ProbeTarget]:
    """A client-rendered SPA's real object-lookup endpoints are
    overwhelmingly REST-style path segments (Juice Shop's
    /rest/products/{id}, /rest/basket/{id}) — never a query string, a
    <form> field, or a JSON body key, so none of the probe-target
    builders above can see this shape at all. Reuses the exact same
    numeric-id detection app.agents.access_control/business_logic
    already rely on for IDOR testing (app.agents.idor.
    find_numeric_id_segment) — same detection, a different question
    (can this segment be broken with an injection payload, vs. can it
    be swapped for another user's id).
    """
    targets = []
    seen: set[tuple[str, int]] = set()
    for url in endpoints:
        found = find_numeric_id_segment(url)
        if found is None:
            continue
        index, _ = found
        if (url, index) in seen:
            continue
        seen.add((url, index))
        targets.append(
            ProbeTarget(url=url, method="GET", param_name=_path_segment_label(url, index), path_segment_index=index)
        )
    return targets


def build_request(target: ProbeTarget, value: str) -> tuple[str, str | None, str | None]:
    if target.path_segment_index is not None:
        # Percent-encode the payload before it goes into the path itself
        # — unlike a query string (built via urlencode above) or a JSON
        # body, substitute_path_segment does a raw string swap, and an
        # un-encoded payload (a literal '<', '"', or space from an
        # XSS/SQLi payload) would produce an invalid URL rather than the
        # same request a real client sends. A real browser/HTTP client
        # always percent-encodes a path segment before it goes on the
        # wire, and every real router/framework decodes it straight
        # back — this changes nothing about what the target application
        # actually receives.
        encoded = quote(value, safe="")
        return substitute_path_segment(target.url, target.path_segment_index, encoded), None, None
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
