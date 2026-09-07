"""Tests for app.integrations.portswigger.client — the scraper backing
the VGS report-builder's "Load from PortSwigger" action. Real local HTTP
fixture server, no network access to portswigger.net (same treatment as
app.integrations.slack/jira/vgs's own client tests)."""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from app.integrations.portswigger.client import PortswigerFetchError, fetch_topics


def _make_fixture_server():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if self.path == "/good1":
                body = (
                    b"<html><head><meta name=\"description\" content=\"SQLi info\"></head>"
                    b"<body><h1>SQL Injection</h1></body></html>"
                )
            elif self.path == "/good2":
                body = (
                    b"<html><head><meta name=\"description\" content=\"XSS info\"></head>"
                    b"<body><h1>Cross-Site Scripting</h1></body></html>"
                )
            elif self.path == "/no-meta":
                body = b"<html><body><h1>No Description Topic</h1></body></html>"
            else:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):  # noqa: A002
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


async def test_fetch_topics_extracts_title_and_description_and_skips_broken_urls():
    server, thread = _make_fixture_server()
    try:
        host, port = server.server_address
        base = f"http://{host}:{port}"
        topics = await fetch_topics(urls=[f"{base}/good1", f"{base}/missing", f"{base}/good2"])

        assert len(topics) == 2
        assert topics[0].title == "SQL Injection"
        assert topics[0].description == "SQLi info"
        assert topics[0].url == f"{base}/good1"
        assert topics[1].title == "Cross-Site Scripting"
        assert topics[1].description == "XSS info"
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_fetch_topics_defaults_description_to_empty_when_no_meta_tag():
    server, thread = _make_fixture_server()
    try:
        host, port = server.server_address
        base = f"http://{host}:{port}"
        topics = await fetch_topics(urls=[f"{base}/no-meta"])
        assert len(topics) == 1
        assert topics[0].title == "No Description Topic"
        assert topics[0].description == ""
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_fetch_topics_raises_when_every_url_fails():
    server, thread = _make_fixture_server()
    try:
        host, port = server.server_address
        base = f"http://{host}:{port}"
        with pytest.raises(PortswigerFetchError):
            await fetch_topics(urls=[f"{base}/missing"])
    finally:
        server.shutdown()
        thread.join(timeout=2)
