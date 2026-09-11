import base64

import pytest

from app.importers.burp_file_importer import BurpFileImporter

_REQUEST_RAW = "GET /users/1?verbose=true HTTP/1.1\r\nHost: api.example.test\r\nAccept: application/json\r\n\r\n"
_RESPONSE_RAW = 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"id": 1}'


def _items_xml(*item_bodies: str) -> str:
    return (
        '<?xml version="1.0"?>\n<items burpVersion="2024.1">\n' + "\n".join(item_bodies) + "\n</items>\n"
    )


def _item_xml(
    *,
    url: str = "https://api.example.test/users/1?verbose=true",
    method: str = "GET",
    status: str = "200",
    time: str = "Tue Mar 31 16:23:42 EDT 2026",
    request_raw: str = _REQUEST_RAW,
    response_raw: str = _RESPONSE_RAW,
) -> str:
    request_b64 = base64.b64encode(request_raw.encode()).decode()
    response_b64 = base64.b64encode(response_raw.encode()).decode()
    return f"""<item>
  <time>{time}</time>
  <url><![CDATA[{url}]]></url>
  <host ip="93.184.216.34">api.example.test</host>
  <port>443</port>
  <protocol>https</protocol>
  <method><![CDATA[{method}]]></method>
  <status>{status}</status>
  <request base64="true"><![CDATA[{request_b64}]]></request>
  <response base64="true"><![CDATA[{response_b64}]]></response>
</item>"""


def test_binary_project_save_raises_clear_error_not_silent_failure(tmp_path):
    # Burp's proprietary full-project ".burp" save never starts with an
    # XML declaration — a few bytes of its real binary header is enough
    # to trigger the same rejection without needing a genuine sample.
    binary_path = tmp_path / "project.burp"
    binary_path.write_bytes(b"\x00\x01BURP_PROJECT_FILE_V2\x00\x00")

    with pytest.raises(NotImplementedError, match="proprietary full-project save"):
        BurpFileImporter().parse(str(binary_path))


def test_rejects_xml_with_no_items_root(tmp_path):
    xml_path = tmp_path / "not-items.xml"
    xml_path.write_text('<?xml version="1.0"?>\n<somethingelse></somethingelse>\n')

    with pytest.raises(ValueError, match="no top-level <items>"):
        BurpFileImporter().parse(str(xml_path))


def test_parses_a_single_item_into_a_real_http_interaction(tmp_path):
    xml_path = tmp_path / "export.xml"
    xml_path.write_text(_items_xml(_item_xml()))

    interactions = BurpFileImporter().parse(str(xml_path))

    assert len(interactions) == 1
    interaction = interactions[0]
    assert interaction.source == "burp_file"
    assert interaction.request.method == "GET"
    assert interaction.request.url == "https://api.example.test/users/1?verbose=true"
    assert interaction.request.headers["Host"] == "api.example.test"
    assert interaction.request.headers["Accept"] == "application/json"
    assert interaction.request.body is None
    assert interaction.response.status == 200
    assert interaction.response.headers["Content-Type"] == "application/json"
    assert interaction.response.body == '{"id": 1}'
    # "Tue Mar 31 16:23:42 EDT 2026" parsed for real, not left at the
    # tolerant "now" fallback.
    assert interaction.timestamp.year == 2026
    assert interaction.timestamp.month == 3
    assert interaction.timestamp.day == 31


def test_parses_multiple_items_and_a_post_with_a_body(tmp_path):
    post_request = (
        "POST /users HTTP/1.1\r\nHost: api.example.test\r\nContent-Type: application/json\r\n\r\n"
        '{"name": "Alice"}'
    )
    xml_path = tmp_path / "export.xml"
    xml_path.write_text(
        _items_xml(
            _item_xml(),
            _item_xml(
                url="https://api.example.test/users",
                method="POST",
                status="201",
                request_raw=post_request,
                response_raw="HTTP/1.1 201 Created\r\n\r\n",
            ),
        )
    )

    interactions = BurpFileImporter().parse(str(xml_path))

    assert len(interactions) == 2
    post = interactions[1]
    assert post.request.method == "POST"
    assert post.request.body == '{"name": "Alice"}'
    assert post.response.status == 201


def test_skips_an_item_with_no_url_rather_than_crashing(tmp_path):
    malformed_item = "<item>\n  <method>GET</method>\n</item>"
    xml_path = tmp_path / "export.xml"
    xml_path.write_text(_items_xml(malformed_item, _item_xml()))

    interactions = BurpFileImporter().parse(str(xml_path))

    assert len(interactions) == 1


def test_falls_back_to_now_for_an_unparseable_timestamp(tmp_path):
    xml_path = tmp_path / "export.xml"
    xml_path.write_text(_items_xml(_item_xml(time="not-a-real-timestamp")))

    interactions = BurpFileImporter().parse(str(xml_path))

    assert len(interactions) == 1
    assert interactions[0].timestamp is not None


def test_rejects_xxe_attempt_via_external_entity_declaration(tmp_path):
    # A billion-laughs/XXE-shaped upload — defusedxml must refuse this
    # outright (DOCTYPE with an ENTITY declaration), not attempt to
    # resolve it and not silently succeed with the entity left unexpanded.
    xxe_path = tmp_path / "xxe.xml"
    xxe_path.write_text(
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE items [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n'
        "<items>\n"
        f"{_item_xml(url='&xxe;')}\n"
        "</items>\n"
    )

    with pytest.raises(Exception):  # noqa: B017 — defusedxml's own EntitiesForbidden, not asserted by name
        BurpFileImporter().parse(str(xxe_path))
