from app.ai.verdict import parse_finding_proposal, parse_verdict


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


def test_uses_the_last_json_block_when_the_model_self_corrects_mid_response():
    """The real bug this closes: a real Claude response was observed
    visibly reconsidering mid-answer ("Wait, let me reconsider...")
    between two separate ```json fenced blocks, with the FIRST saying
    vulnerable:false and the SECOND (its actual final, settled answer)
    saying vulnerable:true. The old single-anchored-match parser treated
    the whole multi-block response as unparseable and returned None,
    discarding the model's real final verdict."""
    raw = (
        "```json\n"
        '{"vulnerable": false, "confidence": "high", "reasoning": "initial read"}\n'
        "```\n\n"
        "Wait, let me reconsider — on closer inspection this is actually exploitable.\n\n"
        "```json\n"
        '{"vulnerable": true, "confidence": "high", "reasoning": "corrected final answer"}\n'
        "```"
    )
    verdict = parse_verdict(raw)
    assert verdict is not None
    assert verdict.vulnerable is True
    assert verdict.reasoning == "corrected final answer"


def test_returns_none_for_unparseable_content():
    assert parse_verdict("I'm not sure, let me think about this...") is None


def test_returns_none_for_json_missing_required_fields():
    assert parse_verdict('{"vulnerable": true}') is None


_FULL_FINDING_PROPOSAL_FIELDS = {
    "title": "SQL injection in login form",
    "severity": "Critical",
    "cwe_id": "CWE-89",
    "owasp_2025_category": "A05 Injection",
    "affected_endpoint": "http://target/doLogin",
    "plain_language_summary": "x",
    "technical_description": "x",
    "remediation": "x",
    "evidence": "x",
    "request_raw": "curl -X POST http://target/doLogin -d \"uid=admin' OR '1'='1\"",
    "response_raw": "HTTP/1.1 200 OK\nHello Admin User",
}


def test_parses_a_full_finding_proposal():
    import json

    proposal = parse_finding_proposal(json.dumps(_FULL_FINDING_PROPOSAL_FIELDS))
    assert proposal is not None
    assert proposal.title == "SQL injection in login form"
    assert proposal.request_raw.startswith("curl")
    assert proposal.payload is None
    assert proposal.poc_url is None


def test_finding_proposal_missing_request_raw_is_rejected():
    """request_raw/response_raw are required (not optional) — the same
    "never guess a Finding into existence" discipline as every other
    required field here: a proposal with no re-checkable raw evidence
    attached must fail to parse entirely, not produce a Finding with an
    empty Evidence row."""
    import json

    fields = dict(_FULL_FINDING_PROPOSAL_FIELDS)
    del fields["request_raw"]
    assert parse_finding_proposal(json.dumps(fields)) is None


def test_finding_proposal_missing_response_raw_is_rejected():
    import json

    fields = dict(_FULL_FINDING_PROPOSAL_FIELDS)
    del fields["response_raw"]
    assert parse_finding_proposal(json.dumps(fields)) is None


def test_finding_proposal_accepts_optional_payload_and_poc_fields():
    import json

    fields = dict(_FULL_FINDING_PROPOSAL_FIELDS)
    fields["payload"] = "admin' OR '1'='1"
    fields["poc_url"] = "http://target/search.jsp"
    fields["poc_param"] = "query"
    proposal = parse_finding_proposal(json.dumps(fields))
    assert proposal is not None
    assert proposal.payload == "admin' OR '1'='1"
    assert proposal.poc_url == "http://target/search.jsp"
    assert proposal.poc_param == "query"
