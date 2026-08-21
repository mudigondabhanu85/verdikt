"""Client for Slack's incoming-webhook API (§8 reporting/ops gap),
documented at https://api.slack.com/messaging/webhooks — a POST of
{"text": "..."} to a per-workspace URL, no OAuth/API-key management
needed on our side. Not live-testable against a real Slack workspace in
this sandbox; built against the documented contract and tested against
a local fixture server shaped like it (same treatment as
app.integrations.burp.rest_client for Burp Professional).
"""

import httpx


class SlackNotificationError(RuntimeError):
    pass


class SlackClient:
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
        try:
            async with httpx.AsyncClient(transport=self._transport, timeout=self._timeout) as client:
                response = await client.post(self._webhook_url, json={"text": text})
        except httpx.RequestError as exc:
            raise SlackNotificationError(f"Could not reach Slack webhook: {exc}") from exc
        if response.status_code != 200:
            raise SlackNotificationError(
                f"Slack webhook rejected the message: {response.status_code} {response.text}"
            )
