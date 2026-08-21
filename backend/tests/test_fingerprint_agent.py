import httpx

from app.agents.fingerprint import FingerprintAgent


def _response(
    url: str, *, status=200, headers=None, cookies=None, text="", content_type="text/html"
) -> httpx.Response:
    all_headers = {"content-type": content_type}
    if headers:
        all_headers.update(headers)
    raw_headers = list(all_headers.items())
    if cookies:
        raw_headers += [("set-cookie", c) for c in cookies]
    request = httpx.Request("GET", url)
    return httpx.Response(status, headers=raw_headers, text=text, request=request)


def test_detects_server_and_powered_by_headers():
    responses = {
        "http://site.test/": _response(
            "http://site.test/", headers={"server": "nginx/1.25.3", "x-powered-by": "Express"}
        )
    }
    fp = FingerprintAgent().run(responses)
    assert "nginx" in fp.server_software
    assert "Express" in fp.backend_languages


def test_detects_language_from_session_cookie():
    responses = {
        "http://site.test/": _response(
            "http://site.test/", cookies=["PHPSESSID=abc123; Path=/; HttpOnly"]
        )
    }
    fp = FingerprintAgent().run(responses)
    assert "PHP" in fp.backend_languages


def test_detects_react_and_django_markers_in_html():
    html = '<html><body><div id="root" data-reactroot=""></div><form>{% csrf_token %}<input name="csrfmiddlewaretoken"></form></body></html>'
    responses = {"http://site.test/": _response("http://site.test/", text=html)}
    fp = FingerprintAgent().run(responses)
    assert "React" in fp.frontend_frameworks
    assert "Python (Django)" in fp.backend_languages


def test_detects_wordpress_from_asset_paths():
    html = '<html><head><link rel="stylesheet" href="/wp-content/themes/x/style.css"></head></html>'
    responses = {"http://site.test/": _response("http://site.test/", text=html)}
    fp = FingerprintAgent().run(responses)
    assert "WordPress" in fp.cms


def test_detects_python_from_error_page():
    text = "Traceback (most recent call last):\n  File \"app.py\", line 10\nZeroDivisionError"
    responses = {
        "http://site.test/crash": _response(
            "http://site.test/crash", status=500, text=text, content_type="text/plain"
        )
    }
    fp = FingerprintAgent().run(responses)
    assert "Python" in fp.backend_languages


def test_non_html_json_response_does_not_trigger_html_markers():
    responses = {
        "http://site.test/api": _response(
            "http://site.test/api", text='{"wp-content": "not actually wordpress"}', content_type="application/json"
        )
    }
    fp = FingerprintAgent().run(responses)
    assert fp.is_empty


def test_empty_response_set_yields_empty_fingerprint():
    fp = FingerprintAgent().run({})
    assert fp.is_empty
    assert fp.to_dict() == {
        "server_software": [],
        "backend_languages": [],
        "frontend_frameworks": [],
        "cms": [],
    }
