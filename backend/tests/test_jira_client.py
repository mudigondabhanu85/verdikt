import base64
import json

import httpx
import pytest

from app.integrations.jira.client import JiraClient, JiraTicketError


def _handler(request: httpx.Request) -> httpx.Response:
    if str(request.url) == "https://jira.example.test/rest/api/3/issue" and request.method == "POST":
        auth = request.headers.get("authorization", "")
        assert auth.startswith("Basic ")
        decoded = base64.b64decode(auth.removeprefix("Basic ")).decode()
        assert decoded == "analyst@example.io:secret-token"
        body = json.loads(request.content.decode())
        assert body["fields"]["project"]["key"] == "SEC"
        assert body["fields"]["issuetype"]["name"] == "Task"
        return httpx.Response(201, json={"id": "10001", "key": "SEC-42", "self": "https://jira.example.test/rest/api/3/issue/10001"})
    return httpx.Response(404)


async def test_create_issue_returns_key_and_browsable_url():
    client = JiraClient(
        "https://jira.example.test", "analyst@example.io", "secret-token", transport=httpx.MockTransport(_handler)
    )
    result = await client.create_issue(
        project_key="SEC", issue_type="Task", summary="Test finding", description="details here"
    )
    assert result == {"key": "SEC-42", "url": "https://jira.example.test/browse/SEC-42"}


async def test_create_issue_raises_on_failure_status():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"errors": {"project": "project is required"}})

    client = JiraClient("https://jira.example.test", "a@b.io", "tok", transport=httpx.MockTransport(handler))
    with pytest.raises(JiraTicketError, match="issue creation failed"):
        await client.create_issue(project_key="SEC", issue_type="Task", summary="x", description="y")


async def test_create_issue_raises_on_connection_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Connection refused", request=request)

    client = JiraClient("https://jira.example.test", "a@b.io", "tok", transport=httpx.MockTransport(handler))
    with pytest.raises(JiraTicketError, match="Could not reach Jira"):
        await client.create_issue(project_key="SEC", issue_type="Task", summary="x", description="y")
