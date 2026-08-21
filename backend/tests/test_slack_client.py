import httpx
import pytest

from app.integrations.slack.client import SlackClient, SlackNotificationError


async def test_post_message_succeeds_on_200():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.content
        return httpx.Response(200, text="ok")

    client = SlackClient("https://hooks.slack.example/services/x", transport=httpx.MockTransport(handler))
    await client.post_message("hello from verdikt")
    assert b"hello from verdikt" in captured["body"]


async def test_post_message_raises_on_non_200():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="no_service")

    client = SlackClient("https://hooks.slack.example/services/x", transport=httpx.MockTransport(handler))
    with pytest.raises(SlackNotificationError, match="rejected"):
        await client.post_message("hello")


async def test_post_message_raises_on_connection_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Connection refused", request=request)

    client = SlackClient("https://hooks.slack.example/services/x", transport=httpx.MockTransport(handler))
    with pytest.raises(SlackNotificationError, match="Could not reach"):
        await client.post_message("hello")
