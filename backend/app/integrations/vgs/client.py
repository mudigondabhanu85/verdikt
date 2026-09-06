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
        auth_type: str | None = None,
        auth_value: str | None = None,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 30.0,
    ):
        self._webhook_url = webhook_url
        self._auth_type = auth_type
        self._auth_value = auth_value
        self._transport = transport
        self._timeout = timeout

    def _request_kwargs(self) -> dict[str, Any]:
        """The real, connected VGS instance has no auth of its own
        (confirmed against its actual source — an unauthenticated local
        report-builder API), so these stay opt-in for any other
        findings-ingestion webhook an org might point this at instead
        (a hosted/gatewayed VGS deployment, etc.). No fixed spec exists
        for what header shape "api_key" auth should take across
        arbitrary targets — X-API-Key is a reasonable, common default;
        an org whose target expects something else should use
        bearer_token or basic instead.
        """
        if self._auth_type is None or not self._auth_value:
            return {}
        if self._auth_type == "api_key":
            return {"headers": {"X-API-Key": self._auth_value}}
        if self._auth_type == "bearer_token":
            return {"headers": {"Authorization": f"Bearer {self._auth_value}"}}
        if self._auth_type == "basic":
            username, _, password = self._auth_value.partition(":")
            return {"auth": httpx.BasicAuth(username, password)}
        raise VGSPushError(f"Unknown VGSConfig.auth_type: {self._auth_type!r}")

    async def push_findings(self, scan_run_id: str, findings: list[dict[str, Any]]) -> None:
        payload = {"source": "ai-multi-agent", "scan_run_id": scan_run_id, "findings": findings}
        try:
            async with httpx.AsyncClient(transport=self._transport, timeout=self._timeout) as client:
                response = await client.post(self._webhook_url, json=payload, **self._request_kwargs())
        except httpx.RequestError as exc:
            raise VGSPushError(f"Could not reach VGS webhook: {exc}") from exc
        if response.status_code >= 300:
            raise VGSPushError(f"VGS webhook rejected the push: {response.status_code} {response.text}")
