import json

import pytest

from app.importers.postman_importer import PostmanImporter

_COLLECTION = {
    "info": {"name": "Sample Collection", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/"},
    "item": [
        {
            "name": "Get user",
            "request": {
                "method": "GET",
                "header": [{"key": "Accept", "value": "application/json"}],
                "url": {"raw": "https://api.example.test/users/1?verbose=true"},
            },
        },
        {
            "name": "Folder",
            "item": [
                {
                    "name": "Create user",
                    "request": {
                        "method": "POST",
                        "header": [{"key": "Content-Type", "value": "application/json"}],
                        "url": "https://api.example.test/users",
                        "body": {"mode": "raw", "raw": '{"name": "Alice"}'},
                    },
                }
            ],
        },
    ],
}


def test_parses_top_level_and_nested_folder_requests(tmp_path):
    collection_path = tmp_path / "collection.json"
    collection_path.write_text(json.dumps(_COLLECTION))

    interactions = PostmanImporter().parse(str(collection_path))
    assert len(interactions) == 2
    assert all(i.source == "postman_import" for i in interactions)

    get_interaction = next(i for i in interactions if i.request.method == "GET")
    assert get_interaction.request.url == "https://api.example.test/users/1?verbose=true"
    assert get_interaction.request.headers == {"Accept": "application/json"}

    post_interaction = next(i for i in interactions if i.request.method == "POST")
    assert post_interaction.request.url == "https://api.example.test/users"
    assert post_interaction.request.body == '{"name": "Alice"}'


def test_rejects_non_postman_document(tmp_path):
    not_a_collection = tmp_path / "not_a_collection.json"
    not_a_collection.write_text(json.dumps({"hello": "world"}))

    with pytest.raises(ValueError, match="not a Postman collection"):
        PostmanImporter().parse(str(not_a_collection))
