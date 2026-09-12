import json

import pytest

from app.importers.openapi_importer import OpenApiImporter

_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "Sample API", "version": "1.0"},
    "servers": [{"url": "https://api.example.test/v1"}],
    "paths": {
        "/users/{id}": {
            "parameters": [{"name": "id", "in": "path", "schema": {"type": "integer"}}],
            "get": {
                "parameters": [
                    {"name": "verbose", "in": "query", "schema": {"type": "boolean"}, "example": True},
                    {"name": "X-Trace-Id", "in": "header", "example": "abc123"},
                ]
            },
        },
        "/users": {
            "post": {
                "requestBody": {
                    "content": {
                        "application/json": {"example": {"name": "Alice", "email": "alice@example.test"}}
                    }
                }
            }
        },
    },
}


def test_parses_get_operation_with_path_and_query_params(tmp_path):
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps(_SPEC))

    interactions = OpenApiImporter().parse(str(spec_path))
    get_interaction = next(i for i in interactions if i.request.method == "GET")

    # The query string must be baked into the URL itself, not just kept
    # in the separate query_params field — see
    # test_query_params_are_embedded_in_the_url_so_they_get_fuzzed for
    # why (app.agents.recon._extract_query_params, the only thing that
    # ever turns this into a fuzzable parameter, reads it off the URL).
    assert get_interaction.request.url == "https://api.example.test/v1/users/1?verbose=True"
    assert get_interaction.request.query_params == {"verbose": "True"}
    assert get_interaction.request.headers == {"X-Trace-Id": "abc123"}
    assert get_interaction.response.status is None
    assert get_interaction.source == "openapi_import"


def test_parses_post_operation_with_json_body_example(tmp_path):
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps(_SPEC))

    interactions = OpenApiImporter().parse(str(spec_path))
    post_interaction = next(i for i in interactions if i.request.method == "POST")

    assert post_interaction.request.url == "https://api.example.test/v1/users"
    assert json.loads(post_interaction.request.body) == {"name": "Alice", "email": "alice@example.test"}


def test_parses_yaml_spec_too(tmp_path):
    import yaml

    spec_path = tmp_path / "spec.yaml"
    spec_path.write_text(yaml.safe_dump(_SPEC))

    interactions = OpenApiImporter().parse(str(spec_path))
    assert len(interactions) == 2


def test_query_params_are_embedded_in_the_url_so_they_get_fuzzed(tmp_path):
    """Regression test for a real gap found live: OpenApiImporter used
    to put a declared query parameter (e.g. a search endpoint's
    "?product_id=&q=") only in HttpRequest.query_params, never in the
    URL string itself. app.agents.traffic_seed.seed_from_imported_traffic
    — the only bridge from an imported interaction to something the
    injection/xss agents actually fuzz — extracts query parameters via
    app.agents.recon._extract_query_params(url), which parses them out
    of the URL's own querystring and never looks at query_params at all.
    A HAR/Postman/Burp capture always has its query string baked into
    the URL already (it's a real request that was actually sent), so
    this only ever affected OpenAPI imports — and it meant every
    OpenAPI-declared GET query parameter silently never got tested,
    with no visible error, across an entire scan."""
    from app.agents.recon import _extract_query_params

    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps(_SPEC))

    interactions = OpenApiImporter().parse(str(spec_path))
    get_interaction = next(i for i in interactions if i.request.method == "GET")

    extracted = _extract_query_params(get_interaction.request.url)
    assert [p.name for p in extracted] == ["verbose"]
    assert extracted[0].sample_value == "True"


def test_rejects_non_openapi_document(tmp_path):
    not_a_spec = tmp_path / "not_a_spec.json"
    not_a_spec.write_text(json.dumps({"hello": "world"}))

    with pytest.raises(ValueError, match="not an OpenAPI"):
        OpenApiImporter().parse(str(not_a_spec))
