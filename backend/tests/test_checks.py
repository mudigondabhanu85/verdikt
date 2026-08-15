import httpx

from app.agents.checks import CHECKS, FetchedPage, run_all_checks

GOOD_HEADERS = {
    "strict-transport-security": "max-age=63072000",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "geolocation=()",
}


def page(headers: dict | None = None, text: str = "<html></html>", scheme: str = "https", status_code: int = 200, tls_version: str | None = None) -> FetchedPage:
    return FetchedPage(
        url="https://example.test/",
        status_code=status_code,
        headers=httpx.Headers(headers or {}),
        text=text,
        scheme=scheme,
        tls_version=tls_version,
    )


def test_fully_hardened_page_has_no_hits():
    hits = run_all_checks(page(GOOD_HEADERS))
    assert hits == []


def test_missing_hsts_only_flagged_over_https():
    assert len(CHECKS["missing-hsts"](page({}))) == 1
    assert CHECKS["missing-hsts"](page({}, scheme="http")) == []


def test_missing_csp():
    assert len(CHECKS["missing-csp"](page({}))) == 1
    assert CHECKS["missing-csp"](page({"content-security-policy": "default-src 'self'"})) == []


def test_x_frame_options_not_flagged_when_csp_has_frame_ancestors():
    headers = {"content-security-policy": "frame-ancestors 'self'"}
    assert CHECKS["missing-x-frame-options"](page(headers)) == []


def test_x_frame_options_flagged_without_either_protection():
    assert len(CHECKS["missing-x-frame-options"](page({}))) == 1
    assert CHECKS["missing-x-frame-options"](page({"x-frame-options": "DENY"})) == []


def test_x_content_type_options_requires_nosniff_value():
    assert len(CHECKS["missing-x-content-type-options"](page({"x-content-type-options": "garbage"}))) == 1
    assert CHECKS["missing-x-content-type-options"](page({"x-content-type-options": "nosniff"})) == []


def test_cookie_checks_flag_each_missing_attribute():
    headers = {"set-cookie": "session=abc123; Path=/"}
    p = page(headers)
    assert len(CHECKS["cookie-missing-secure"](p)) == 1
    assert len(CHECKS["cookie-missing-httponly"](p)) == 1
    assert len(CHECKS["cookie-missing-samesite"](p)) == 1


def test_cookie_fully_flagged_is_clean():
    headers = {"set-cookie": "session=abc123; Path=/; Secure; HttpOnly; SameSite=Lax"}
    p = page(headers)
    assert CHECKS["cookie-missing-secure"](p) == []
    assert CHECKS["cookie-missing-httponly"](p) == []
    assert CHECKS["cookie-missing-samesite"](p) == []


def test_cookie_secure_not_flagged_over_http():
    headers = {"set-cookie": "session=abc123"}
    p = page(headers, scheme="http")
    assert CHECKS["cookie-missing-secure"](p) == []


def test_server_version_disclosure():
    assert CHECKS["server-version-disclosure"](page({})) == []
    hits = CHECKS["server-version-disclosure"](page({"server": "nginx/1.18.0"}))
    assert len(hits) == 1
    assert "nginx/1.18.0" in hits[0].extra["server_value"]


def test_verbose_error_stack_trace():
    clean = page({}, text="<html><body>Not found</body></html>")
    assert CHECKS["verbose-error-stack-trace"](clean) == []

    dirty = page({}, text="Traceback (most recent call last):\n  File 'app.py'")
    assert len(CHECKS["verbose-error-stack-trace"](dirty)) == 1


def test_directory_listing_enabled():
    clean = page({}, text="<html><body>Welcome</body></html>")
    assert CHECKS["directory-listing-enabled"](clean) == []

    dirty = page({}, text="<html><title>Index of /uploads</title><body>Parent Directory</body></html>")
    assert len(CHECKS["directory-listing-enabled"](dirty)) == 1


def test_plaintext_http():
    assert CHECKS["plaintext-http"](page({}, scheme="http")) != []
    assert CHECKS["plaintext-http"](page({}, scheme="https")) == []


def test_weak_tls_version():
    assert CHECKS["weak-tls-version"](page({}, tls_version="TLSv1")) != []
    assert CHECKS["weak-tls-version"](page({}, tls_version="TLSv1.2")) == []
    assert CHECKS["weak-tls-version"](page({}, tls_version=None)) == []


def test_autocomplete_enabled_password_field():
    headers = {"content-type": "text/html"}
    unsafe = page(headers, text='<form><input type="password" name="pw"></form>')
    assert len(CHECKS["autocomplete-enabled-password-field"](unsafe)) == 1

    safe = page(headers, text='<form><input type="password" name="pw" autocomplete="new-password"></form>')
    assert CHECKS["autocomplete-enabled-password-field"](safe) == []


def test_autocomplete_check_skips_non_html_responses():
    p = page({"content-type": "application/json"}, text='{"password": "not a form"}')
    assert CHECKS["autocomplete-enabled-password-field"](p) == []
