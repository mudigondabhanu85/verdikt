"""Client for Burp Suite Professional's local Scanner REST API (§4/§11),
documented at
https://portswigger.net/burp/documentation/desktop/tools/scanner/rest-api
— a self-hosted, single-analyst-facing API distinct from Burp
Enterprise's separate GraphQL API (a future extension, not built here).

Not live-testable in this sandbox: the Burp installed here is Community
Edition, which has no REST API at all (Pro/Enterprise-only). Built
against the documented request/response shapes; tests exercise it via
httpx.MockTransport fixtures shaped like Burp's own documented examples.
"""

import asyncio

import httpx


class BurpScanError(RuntimeError):
    pass


class BurpRestClient:
    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        *,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 30.0,
    ):
        self._base_url = base_url.rstrip("/")
        # Burp's REST API key, when the "Service running on" setting has
        # one configured, is a path segment (/<api_key>/v0.1/...), not a
        # header or query param — kept as a constructor arg so callers
        # don't need to know that detail.
        self._api_key = api_key
        self._transport = transport
        self._timeout = timeout

    def _url(self, path: str) -> str:
        prefix = f"/{self._api_key}" if self._api_key else ""
        return f"{self._base_url}{prefix}{path}"

    async def start_scan(
        self, urls: list[str], *, scan_configurations: list[str] | None = None
    ) -> str:
        """POST /v0.1/scan. Burp responds 201 Created with a Location
        header pointing at the new scan's status URL; returns the task id
        parsed out of that URL.
        """
        body: dict = {"urls": urls}
        if scan_configurations:
            body["scan_configurations"] = [
                {"name": name, "type": "NamedConfiguration"} for name in scan_configurations
            ]

        try:
            async with httpx.AsyncClient(transport=self._transport, timeout=self._timeout) as client:
                response = await client.post(self._url("/v0.1/scan"), json=body)
        except httpx.RequestError as exc:
            # A connection-level failure (refused, DNS, timeout) here
            # previously propagated uncaught past this class entirely —
            # the route above only excepts BurpScanError, so callers got
            # an unhandled 500 instead of the documented, clean 502
            # "Could not start Burp scan: ..." response. Found via a
            # real E2E run against a genuinely unreachable Burp URL.
            raise BurpScanError(f"Could not reach Burp at {self._base_url}: {exc}") from exc

        if response.status_code not in (201, 202):
            raise BurpScanError(
                f"Burp scan creation failed: {response.status_code} {response.text}"
            )
        location = response.headers.get("location")
        if not location:
            raise BurpScanError("Burp scan creation response missing Location header")
        return location.rstrip("/").rsplit("/", 1)[-1]

    async def get_scan_status(self, task_id: str) -> dict:
        """GET /v0.1/scan/{task_id}. Returns the raw documented body:
        {"scan_status": ..., "scan_metrics": {...}, "issue_events": [...]}.
        """
        try:
            async with httpx.AsyncClient(transport=self._transport, timeout=self._timeout) as client:
                response = await client.get(self._url(f"/v0.1/scan/{task_id}"))
        except httpx.RequestError as exc:
            raise BurpScanError(f"Could not reach Burp at {self._base_url}: {exc}") from exc

        if response.status_code != 200:
            raise BurpScanError(
                f"Could not fetch Burp scan status: {response.status_code} {response.text}"
            )
        return response.json()

    async def wait_for_completion(
        self, task_id: str, *, poll_interval: float = 5.0, timeout: float = 3600.0
    ) -> dict:
        elapsed = 0.0
        while True:
            status_body = await self.get_scan_status(task_id)
            if status_body.get("scan_status") in ("succeeded", "failed", "paused"):
                return status_body
            if elapsed >= timeout:
                raise BurpScanError(f"Burp scan {task_id} did not complete within {timeout}s")
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval

    @staticmethod
    def extract_issues(status_body: dict) -> list[dict]:
        return [
            event["issue"]
            for event in status_body.get("issue_events", [])
            if event.get("type") == "issue_found" and "issue" in event
        ]
