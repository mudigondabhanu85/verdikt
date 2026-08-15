from pathlib import Path

from app.importers.har_importer import HarImporter

FIXTURE = str(Path(__file__).parent / "fixtures" / "sample.har")


def test_parses_all_entries():
    interactions = HarImporter().parse(FIXTURE)
    assert len(interactions) == 2
    assert all(i.source == "har" for i in interactions)


def test_get_request_fields():
    interactions = HarImporter().parse(FIXTURE)
    get_interaction = interactions[0]
    assert get_interaction.request.method == "GET"
    assert get_interaction.request.url == "https://juice-shop.example.test/rest/products/1?lang=en"
    assert get_interaction.request.query_params == {"lang": "en"}
    assert get_interaction.request.headers["Host"] == "juice-shop.example.test"
    assert get_interaction.request.body is None
    assert get_interaction.response.status == 200
    assert "Apple Juice" in get_interaction.response.body
    assert get_interaction.response.timing_ms == 42.5


def test_post_request_body_and_headers():
    interactions = HarImporter().parse(FIXTURE)
    post_interaction = interactions[1]
    assert post_interaction.request.method == "POST"
    assert "a@a.com" in post_interaction.request.body
    assert post_interaction.response.headers["Set-Cookie"].startswith("token=")


def test_timestamps_parsed():
    interactions = HarImporter().parse(FIXTURE)
    assert interactions[0].timestamp.year == 2026
    assert interactions[0].timestamp < interactions[1].timestamp
