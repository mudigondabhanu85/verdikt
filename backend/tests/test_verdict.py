from app.ai.verdict import parse_verdict


def test_parses_bare_json():
    verdict = parse_verdict(
        '{"vulnerable": true, "confidence": "high", "reasoning": "clear signal"}'
    )
    assert verdict is not None
    assert verdict.vulnerable is True
    assert verdict.confidence == "high"


def test_parses_markdown_json_code_fence():
    """The real bug this closes: every real (non-scripted-fake) Claude
    response observed against DVWA wrapped its JSON verdict in a ```json
    code fence despite the prompt asking for raw JSON, and the old parser
    called json.loads() on the raw string with no fence-stripping, so it
    silently returned None — discarding every correct AI-confirmed
    verdict system-wide (injection, XSS, and any other agent using this
    shared parser)."""
    raw = (
        "```json\n"
        '{"vulnerable": true, "confidence": "high", '
        '"reasoning": "MariaDB SQL syntax error triggered by a single quote"}\n'
        "```"
    )
    verdict = parse_verdict(raw)
    assert verdict is not None
    assert verdict.vulnerable is True
    assert verdict.confidence == "high"


def test_parses_plain_code_fence_without_json_language_tag():
    raw = '```\n{"vulnerable": false, "confidence": "medium", "reasoning": "benign"}\n```'
    verdict = parse_verdict(raw)
    assert verdict is not None
    assert verdict.vulnerable is False


def test_parses_json_with_surrounding_whitespace():
    verdict = parse_verdict(
        '\n\n  {"vulnerable": true, "confidence": "low", "reasoning": "weak signal"}  \n'
    )
    assert verdict is not None
    assert verdict.vulnerable is True


def test_returns_none_for_unparseable_content():
    assert parse_verdict("I'm not sure, let me think about this...") is None


def test_returns_none_for_json_missing_required_fields():
    assert parse_verdict('{"vulnerable": true}') is None
