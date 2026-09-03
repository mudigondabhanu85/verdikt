"""Client for pushing findings to VGS (§11) — the user's existing
open-source DAST governance tool. Per §11's explicit recommendation,
this is the decoupled path: VGS stays the system of record for
governance/remediation tracking, and this platform pushes structured
findings to VGS's own ingestion webhook, tagged source: ai-multi-agent,
rather than sharing a database or auth layer. Not live-testable against
a real VGS instance in this sandbox; built against the shape §11
describes and tested against a local fixture server (same treatment as
app.integrations.slack.client for Slack).
"""

from typing import Any

import httpx


class VGSPushError(RuntimeError):
    pass


class VGSClient:
    def __init__(
        self,
        webhook_url: str,
        *,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 30.0,
    ):
        self._webhook_url = webhook_url
        self._transport = transport
        self._timeout = timeout

    async def push_findings(self, scan_run_id: str, findings: list[dict[str, Any]]) -> None:
        payload = {"source": "ai-multi-agent", "scan_run_id": scan_run_id, "findings": findings}
        try:
            async with httpx.AsyncClient(transport=self._transport, timeout=self._timeout) as client:
                response = await client.post(self._webhook_url, json=payload)
        except httpx.RequestError as exc:
            raise VGSPushError(f"Could not reach VGS webhook: {exc}") from exc
        if response.status_code >= 300:
            raise VGSPushError(f"VGS webhook rejected the push: {response.status_code} {response.text}")
