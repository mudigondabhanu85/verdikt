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

    assert get_interaction.request.url == "https://api.example.test/v1/users/1"
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


def test_rejects_non_openapi_document(tmp_path):
    not_a_spec = tmp_path / "not_a_spec.json"
    not_a_spec.write_text(json.dumps({"hello": "world"}))

    with pytest.raises(ValueError, match="not an OpenAPI"):
        OpenApiImporter().parse(str(not_a_spec))
