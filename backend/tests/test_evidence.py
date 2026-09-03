import httpx

from app.agents.evidence import format_request_raw, format_response_raw


def test_format_response_raw_strips_nul_bytes_from_binary_body():
    """A real bug found via §14 live validation against OWASP Juice
    Shop: fetching a real binary asset (a .kdbx file, part of Juice
    Shop's own FTP-directory-listing challenge) during a routine
    header-config crawl produced a response body whose text decoding
    contained literal NUL bytes — Postgres text columns reject those
    outright, crashing the Evidence insert. format_request_raw/
    format_response_raw are the single shared choke point every agent's
    Evidence persistence goes through, so the fix belongs here.
    """
    request = httpx.Request("GET", "http://site.test/file.bin")
    response = httpx.Response(
        200,
        headers={"content-type": "application/octet-stream"},
        content=b"before\x00after",
        request=request,
    )
    formatted = format_response_raw(response)
    assert "\x00" not in formatted
    assert "before" in formatted
    assert "after" in formatted


def test_format_request_raw_strips_nul_bytes_from_binary_body():
    request = httpx.Request("POST", "http://site.test/upload", content=b"before\x00after")
    response = httpx.Response(200, request=request)
    formatted = format_request_raw(response)
    assert "\x00" not in formatted


def test_format_response_raw_leaves_normal_text_unchanged():
    request = httpx.Request("GET", "http://site.test/")
    response = httpx.Response(
        200,
        headers={"content-type": "text/html"},
        text="<html>hello</html>",
        request=request,
    )
    formatted = format_response_raw(response)
    assert "<html>hello</html>" in formatted
    assert "HTTP/1.1 200" in formatted
