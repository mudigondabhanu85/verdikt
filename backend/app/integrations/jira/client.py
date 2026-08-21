"""Client for Jira Cloud's REST API v3 (§8 reporting/ops gap),
documented at
https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/#api-rest-api-3-issue-post
— issue creation via HTTP Basic Auth (email + API token, Jira Cloud's
documented auth for this endpoint) rather than OAuth, matching how an
analyst would actually configure this (a personal API token, not an
OAuth app registration). Not live-testable against a real Jira
instance in this sandbox; built against the documented contract and
tested against a local fixture server shaped like it (same treatment
as app.integrations.burp.rest_client for Burp Professional).
"""

import base64

import httpx


class JiraTicketError(RuntimeError):
    pass


class JiraClient:
    def __init__(
        self,
        base_url: str,
        email: str,
        api_token: str,
        *,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 30.0,
    ):
        self._base_url = base_url.rstrip("/")
        self._email = email
        self._api_token = api_token
        self._transport = transport
        self._timeout = timeout

    def _auth_header(self) -> dict[str, str]:
        raw = f"{self._email}:{self._api_token}".encode()
        return {"Authorization": f"Basic {base64.b64encode(raw).decode()}"}

    async def create_issue(
        self, *, project_key: str, issue_type: str, summary: str, description: str
    ) -> dict[str, str]:
        """Returns {"key": "SEC-123", "url": "https://.../browse/SEC-123"}
        — the browsable issue URL, not the REST API's own "self" link
        (which points at the machine-readable resource, not a page a
        human would want to click)."""
        body = {
            "fields": {
                "project": {"key": project_key},
                "summary": summary,
                "issuetype": {"name": issue_type},
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [{"type": "paragraph", "content": [{"type": "text", "text": description}]}],
                },
            }
        }
        try:
            async with httpx.AsyncClient(transport=self._transport, timeout=self._timeout) as client:
                response = await client.post(
                    f"{self._base_url}/rest/api/3/issue", json=body, headers=self._auth_header()
                )
        except httpx.RequestError as exc:
            raise JiraTicketError(f"Could not reach Jira at {self._base_url}: {exc}") from exc
        if response.status_code not in (200, 201):
            raise JiraTicketError(f"Jira issue creation failed: {response.status_code} {response.text}")

        key = response.json()["key"]
        return {"key": key, "url": f"{self._base_url}/browse/{key}"}
