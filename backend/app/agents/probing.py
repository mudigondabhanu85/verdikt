"""Shared parameter-probing plumbing used by both the Injection and XSS
agents: turning discovered query params / form fields into a uniform
ProbeTarget, and substituting one parameter's value to fetch a response.
"""

from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

import httpx

from app.agents.http_client import ScopedHttpClient
from app.agents.recon import DiscoveredParameter, FormInfo

BASELINE_VALUE = "verdikt1"


@dataclass
class ProbeTarget:
    url: str
    method: str
    param_name: str
    other_fields: dict[str, str] = field(default_factory=dict)


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
            others = {o.name: BASELINE_VALUE for o in form.fields if o.name != f.name}
            targets.append(
                ProbeTarget(url=form.action_url, method=form.method, param_name=f.name, other_fields=others)
            )
    return targets


def build_request(target: ProbeTarget, value: str) -> tuple[str, str | None, str | None]:
    if target.method == "GET":
        parsed = urlsplit(target.url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[target.param_name] = [value]
        new_query = urlencode({k: v[0] for k, v in params.items()})
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, "")), None, None

    body_fields = dict(target.other_fields)
    body_fields[target.param_name] = value
    return target.url, urlencode(body_fields), "application/x-www-form-urlencoded"


async def fetch_with_value(client: ScopedHttpClient, target: ProbeTarget, value: str) -> httpx.Response:
    url, body, content_type = build_request(target, value)
    if body is None:
        return await client.get(url)
    return await client.post(url, body=body, content_type=content_type)
