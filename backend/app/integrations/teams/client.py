"""Client for a Microsoft Teams incoming webhook (Office 365 Connector or
Workflows-based webhook), documented at
https://learn.microsoft.com/microsoftteams/platform/webhooks-and-connectors/how-to/connectors-using
— a POST of a MessageCard-shaped JSON body to a per-channel URL, no
OAuth/bot registration needed on our side. Same treatment as
app.integrations.slack.client.SlackClient: not live-testable against a
real Teams channel in this sandbox; built against the documented contract
and tested against a local fixture server shaped like it.
"""

import httpx


class TeamsNotificationError(RuntimeError):
    pass


class TeamsClient:
    def __init__(
        self,
        webhook_url: str,
        *,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 10.0,
    ):
        self._webhook_url = webhook_url
        self._transport = transport
        self._timeout = timeout

    async def post_message(self, text: str) -> None:
        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "text": text,
        }
        try:
            async with httpx.AsyncClient(transport=self._transport, timeout=self._timeout) as client:
                response = await client.post(self._webhook_url, json=payload)
        except httpx.RequestError as exc:
            raise TeamsNotificationError(f"Could not reach Teams webhook: {exc}") from exc
        if response.status_code != 200:
            raise TeamsNotificationError(
                f"Teams webhook rejected the message: {response.status_code} {response.text}"
            )
