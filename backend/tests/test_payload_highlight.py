from app.reporting.payload_highlight import find_highlight_match, highlight_candidates


def test_literal_payload_wins_when_present():
    assert find_highlight_match("before <script> after", "<script>") == "<script>"


def test_falls_back_to_form_encoded_form():
    text = "GET /vulnerabilities/sqli/?id=%27&Submit=Submit HTTP/1.1"
    assert find_highlight_match(text, "'") == "%27"


def test_falls_back_to_embedded_marker_token():
    text = "<pre>VERDIKT16912b40\n</pre>"
    assert find_highlight_match(text, "; echo VERDIKT16912b40") == "VERDIKT16912b40"


def test_no_match_returns_none():
    assert find_highlight_match("nothing relevant here", "; echo VERDIKT16912b40") is None


def test_no_payload_returns_none():
    assert find_highlight_match("some text", None) is None
    assert find_highlight_match("some text", "") is None


def test_candidates_are_deduplicated_and_ordered():
    # A payload with no spaces/special chars encodes to itself, and has
    # no embedded marker — only one candidate should come back.
    assert highlight_candidates("abc") == ["abc"]
