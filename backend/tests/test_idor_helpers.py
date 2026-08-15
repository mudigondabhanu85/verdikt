from app.agents.idor import find_numeric_id_segment, nearby_ids, substitute_path_segment


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
