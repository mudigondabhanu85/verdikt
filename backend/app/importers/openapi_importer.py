import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlencode

import yaml

from app.importers.base import TrafficImporter
from app.schemas.traffic import HttpInteraction, HttpRequest, HttpResponse

_PATH_PARAM_RE = re.compile(r"\{[^{}]+\}")
_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


class OpenApiImporter(TrafficImporter):
    """Normalizes an OpenAPI/Swagger document (2.0 or 3.x, JSON or YAML —
    yaml.safe_load parses both) into the canonical HttpInteraction shape
    (§4): one interaction per declared operation, no real response (a
    spec was never executed — response.status stays None, same
    convention as every other file-import path's synthetic
    interactions). These land in traffic_interactions exactly like a
    HAR/Burp import and get picked up by
    app.agents.traffic_seed.seed_from_imported_traffic — a fixed
    endpoint list for the scan to hit directly, no crawling needed,
    which is the whole point for an API with no browsable HTML surface.

    Known gap (see traffic_import.py's module-level note): only
    query/header parameters are extracted into structured fields;
    request-body examples are passed through as an opaque JSON string,
    since DiscoveredParameter's JSON-body-key extraction doesn't exist
    yet — the endpoint itself scans, but a JSON-body parameter isn't
    individually fuzzed the way a query-string parameter is.
    """

    def parse(self, file_path: str) -> list[HttpInteraction]:
        with open(file_path, encoding="utf-8") as f:
            spec = yaml.safe_load(f)
        if not isinstance(spec, dict) or "paths" not in spec:
            raise ValueError("not an OpenAPI/Swagger document (no top-level 'paths')")

        base_url = _base_url(spec)
        now = datetime.now(timezone.utc)
        interactions: list[HttpInteraction] = []

        for path, path_item in (spec.get("paths") or {}).items():
            if not isinstance(path_item, dict):
                continue
            path_level_params = path_item.get("parameters") or []
            resolved_path = _substitute_path_params(path)

            for method, operation in path_item.items():
                if method.lower() not in _HTTP_METHODS or not isinstance(operation, dict):
                    continue
                params = [*path_level_params, *(operation.get("parameters") or [])]
                query_params = {
                    p["name"]: str(_example_value(p))
                    for p in params
                    if isinstance(p, dict) and p.get("in") == "query" and p.get("name")
                }
                headers = {
                    p["name"]: str(_example_value(p))
                    for p in params
                    if isinstance(p, dict) and p.get("in") == "header" and p.get("name")
                }
                url = base_url + resolved_path
                if query_params:
                    # app.agents.traffic_seed.seed_from_imported_traffic
                    # (the only thing that ever turns an imported
                    # interaction into a fuzzable DiscoveredParameter)
                    # reads query params out of the URL's own querystring
                    # via app.agents.recon._extract_query_params — never
                    # out of this request's separate structured
                    # query_params field. A real gap found live: every
                    # query-string parameter an OpenAPI spec declared
                    # (e.g. a "?product_id=&q=" search endpoint) silently
                    # never got fuzzed at all, because the URL itself
                    # carried no querystring for a HAR/Postman/Burp
                    # capture would always have baked in. query_params
                    # stays populated too, for any other consumer.
                    url = f"{url}?{urlencode(query_params)}"
                interactions.append(
                    HttpInteraction(
                        request=HttpRequest(
                            method=method.upper(),
                            url=url,
                            headers=headers,
                            query_params=query_params,
                            body=_request_body_example(operation, params),
                        ),
                        response=HttpResponse(status=None),
                        source="openapi_import",
                        timestamp=now,
                    )
                )
        return interactions


def _substitute_path_params(path: str) -> str:
    # "/users/{id}/orders/{orderId}" -> "/users/1/orders/1" — the scanning
    # agents send these URLs as-is, so a literal "{id}" segment would
    # just 404 every time rather than exercising the real endpoint.
    return _PATH_PARAM_RE.sub("1", path)


def _example_value(param: dict) -> Any:
    if "example" in param:
        return param["example"]
    schema = param.get("schema")
    if isinstance(schema, dict) and "example" in schema:
        return schema["example"]
    if "default" in param:
        return param["default"]
    if isinstance(schema, dict) and "default" in schema:
        return schema["default"]
    return "example"


def _request_body_example(operation: dict, params: list) -> str | None:
    # OpenAPI 3.x: requestBody.content.<media-type>.example
    request_body = operation.get("requestBody")
    if isinstance(request_body, dict):
        content = request_body.get("content")
        if isinstance(content, dict):
            for media_type in ("application/json", *content.keys()):
                media = content.get(media_type)
                if isinstance(media, dict) and "example" in media:
                    return _stringify(media["example"])
        return None
    # Swagger 2.0: a "body"-location parameter's schema.example
    for p in params:
        if isinstance(p, dict) and p.get("in") == "body":
            schema = p.get("schema")
            if isinstance(schema, dict) and "example" in schema:
                return _stringify(schema["example"])
    return None


def _stringify(value: Any) -> str:
    if isinstance(value, str):
        return value
    import json

    return json.dumps(value)


def _resolve_server_variables(url: str, variables: object) -> str:
    """OpenAPI 3.x server URLs can contain {variable} templates (common
    in generated specs, e.g. "{environment}.api.example.com" or
    "https://api.example.com/{basePath}") — each declared in
    servers[0].variables with a required `default` value per the spec.
    Left unresolved, these produce interaction URLs with literal,
    permanently-unresolvable placeholder text (can never resolve via
    DNS/HTTP) instead of a real, usable base URL.
    """
    if not isinstance(variables, dict):
        return url
    for name, var_spec in variables.items():
        if isinstance(var_spec, dict) and "default" in var_spec:
            url = url.replace(f"{{{name}}}", str(var_spec["default"]))
    return url


def _base_url(spec: dict) -> str:
    servers = spec.get("servers")  # OpenAPI 3.x
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        server = servers[0]
        url = server.get("url")
        if url:
            url = _resolve_server_variables(str(url), server.get("variables"))
            return url.rstrip("/")
    # Swagger 2.0
    host = spec.get("host")
    if host:
        scheme = (spec.get("schemes") or ["https"])[0]
        base_path = spec.get("basePath") or ""
        return f"{scheme}://{host}{base_path}".rstrip("/")
    return ""
