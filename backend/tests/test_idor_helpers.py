from app.agents.idor import (
    find_numeric_id_segment,
    find_query_identifier,
    nearby_ids,
    sibling_values,
    substitute_path_segment,
    substitute_query_param,
)


def test_find_numeric_id_segment_finds_trailing_id():
    assert find_numeric_id_segment("http://x/rest/basket/6") == (3, "6")


def test_find_numeric_id_segment_ignores_non_numeric_segments():
    assert find_numeric_id_segment("http://x/rest/basket/items") is None


def test_find_numeric_id_segment_finds_last_numeric_when_multiple_present():
    assert find_numeric_id_segment("http://x/rest/products/7/reviews/3") == (5, "3")


def test_substitute_path_segment_replaces_only_target_index():
    url = substitute_path_segment("http://x/rest/basket/6", 3, "7")
    assert url == "http://x/rest/basket/7"


def test_substitute_path_segment_preserves_query_string():
    url = substitute_path_segment("http://x/rest/basket/6?lang=en", 3, "7")
    assert url == "http://x/rest/basket/7?lang=en"


def test_nearby_ids_excludes_original_and_negative():
    assert nearby_ids("6") == ["5", "7"]
    assert nearby_ids("0") == ["1"]


def test_find_query_identifier_returns_first_non_empty_param():
    assert find_query_identifier("http://x/loyalty/points?email=jamie@example.com") == (
        "email",
        "jamie@example.com",
    )


def test_find_query_identifier_returns_none_without_a_query_string():
    assert find_query_identifier("http://x/loyalty/points") is None


def test_find_query_identifier_skips_blank_values():
    assert find_query_identifier("http://x/search?empty=&q=snowboard") == ("q", "snowboard")


def test_substitute_query_param_replaces_only_named_param():
    url = substitute_query_param("http://x/loyalty/points?email=a@x.com&lang=en", "email", "b@x.com")
    assert url == "http://x/loyalty/points?email=b%40x.com&lang=en"


def test_sibling_values_uses_nearby_ids_for_numeric_values():
    assert sibling_values("6") == ["5", "7"]


def test_sibling_values_preserves_domain_for_email_shaped_values():
    values = sibling_values("jamie.r@example.com")
    assert len(values) == 1
    assert values[0].endswith("@example.com")
    assert values[0] != "jamie.r@example.com"
    assert values[0].startswith("verdikt-idor-probe-")


def test_sibling_values_generates_a_fresh_token_for_generic_strings():
    values = sibling_values("standarduser")
    assert len(values) == 1
    assert values[0] != "standarduser"
    assert values[0].startswith("verdikt-idor-probe-")
