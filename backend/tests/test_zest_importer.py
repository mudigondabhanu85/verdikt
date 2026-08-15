import json
from pathlib import Path

import zstandard

from app.importers.zest_importer import ZestImporter

_SAMPLE_ZEST_SCRIPT = {
    "about": "This is a Zest script. For more details about Zest visit https://github.com/zaproxy/zest/",
    "zestVersion": "0.8",
    "title": "Login and view basket",
    "description": "Recorded via Checkmarx Business Flow Recorder",
    "author": "",
    "prefix": "https://juice-shop.example",
    "type": "StandAlone",
    "statements": [
        {
            "elementType": "ZestRequest",
            "url": "https://juice-shop.example/rest/user/login",
            "method": "POST",
            "headers": "Content-Type: application/json\r\nAccept: application/json\r\n",
            "data": '{"email": "admin@juice-sh.op", "password": "admin123"}',
            "response": {
                "elementType": "ZestResponse",
                "url": "https://juice-shop.example/rest/user/login",
                "headers": "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n",
                "body": '{"authentication": {"token": "abc.def.ghi"}}',
                "statusCode": 200,
                "responseTimeInMs": 142,
            },
            "assertions": [],
            "index": 1,
            "enabled": True,
        },
        {
            "elementType": "ZestSetVariable",
            "variableName": "token",
            "index": 2,
            "enabled": True,
        },
        {
            "elementType": "ZestRequest",
            "url": "https://juice-shop.example/rest/basket/1",
            "method": "GET",
            "headers": "Authorization: Bearer abc.def.ghi\r\n",
            "data": None,
            "response": {
                "elementType": "ZestResponse",
                "url": "https://juice-shop.example/rest/basket/1",
                "headers": "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n",
                "body": '{"data": {"id": 1, "Products": []}}',
                "statusCode": 200,
                "responseTimeInMs": 58,
            },
            "assertions": [
                {"elementType": "ZestAssertStatusCode", "code": 200},
            ],
            "index": 3,
            "enabled": True,
        },
        {
            "elementType": "ZestAssertion",
            "rootExpression": {"elementType": "ZestExpressionStatusCode", "code": 200},
            "index": 4,
            "enabled": True,
        },
    ],
    "authentication": [],
    "index": 0,
    "enabled": True,
}


def _write_zst_fixture(tmp_path: Path, script: dict) -> Path:
    raw_json = json.dumps(script).encode("utf-8")
    compressed = zstandard.ZstdCompressor().compress(raw_json)
    zst_path = tmp_path / "sample.zst"
    zst_path.write_bytes(compressed)
    return zst_path


def test_zest_importer_round_trips_real_zstd_compressed_script(tmp_path):
    zst_path = _write_zst_fixture(tmp_path, _SAMPLE_ZEST_SCRIPT)

    interactions = ZestImporter().parse(str(zst_path))

    # Only the two ZestRequest statements become HttpInteractions —
    # ZestSetVariable/ZestAssertion aren't HTTP exchanges.
    assert len(interactions) == 2

    login, basket = interactions
    assert login.source == "zst_traffic"
    assert login.request.method == "POST"
    assert login.request.url == "https://juice-shop.example/rest/user/login"
    assert login.request.headers["Content-Type"] == "application/json"
    assert "admin@juice-sh.op" in login.request.body
    assert login.response.status == 200
    assert "abc.def.ghi" in login.response.body
    assert login.response.timing_ms == 142

    assert basket.request.method == "GET"
    assert basket.request.headers["Authorization"] == "Bearer abc.def.ghi"
    assert basket.request.body is None
    assert basket.response.status == 200


def test_zest_importer_rejects_non_zstd_content(tmp_path):
    bad_path = tmp_path / "not-zstd.zst"
    bad_path.write_bytes(b"this is not zstandard-compressed data")

    try:
        ZestImporter().parse(str(bad_path))
        assert False, "expected a ValueError"
    except ValueError as exc:
        assert "zstandard" in str(exc).lower()


def test_zest_importer_handles_empty_statements(tmp_path):
    script = dict(_SAMPLE_ZEST_SCRIPT)
    script["statements"] = []
    zst_path = _write_zst_fixture(tmp_path, script)

    interactions = ZestImporter().parse(str(zst_path))
    assert interactions == []
