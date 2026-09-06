import uuid

from app.agents.evidence_screenshot import (
    capture_and_store_evidence_screenshot,
    capture_evidence_screenshot,
)
from app.storage.local_disk import get_object_storage

_REALISTIC_REQUEST = (
    "GET /vulnerabilities/sqli/?id=1'&Submit=Submit HTTP/1.1\n"
    "host: localhost:4280\n"
    "cookie: security=low; PHPSESSID=abc123\n"
)
_REALISTIC_RESPONSE = (
    "HTTP/1.1 200 OK\n"
    "content-type: text/html\n\n"
    "You have an error in your SQL syntax; check the manual that corresponds to your "
    "MariaDB server version for the right syntax to use near ''1''' at line 1"
)


async def test_capture_evidence_screenshot_produces_a_real_png():
    png = await capture_evidence_screenshot(
        title="SQL Injection (error-based)",
        request_raw=_REALISTIC_REQUEST,
        response_raw=_REALISTIC_RESPONSE,
    )
    assert png is not None
    # PNG magic bytes.
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    # A real rendered page, not a near-empty placeholder image.
    assert len(png) > 5000


async def test_capture_and_store_evidence_screenshot_persists_a_retrievable_file():
    scan_run_id = uuid.uuid4()
    refs = await capture_and_store_evidence_screenshot(
        scan_run_id=scan_run_id,
        check_id="sqli-error",
        title="SQL Injection (error-based)",
        request_raw=_REALISTIC_REQUEST,
        response_raw=_REALISTIC_RESPONSE,
    )
    assert len(refs) == 1
    key = refs[0]
    assert str(scan_run_id) in key
    assert "sqli-error" in key

    storage = get_object_storage()
    stored_bytes = await storage.get(key)
    assert stored_bytes[:8] == b"\x89PNG\r\n\x1a\n"


async def test_capture_evidence_screenshot_handles_empty_input_gracefully():
    # No request/response text at all is a degenerate but not invalid
    # case — must still return a real image, never raise.
    png = await capture_evidence_screenshot(title="Empty case", request_raw="", response_raw="")
    assert png is not None
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
