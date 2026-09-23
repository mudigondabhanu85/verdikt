import pytest
from fastapi import HTTPException

from app.auth import require_api_key


@pytest.mark.asyncio
async def test_require_api_key_allows_everything_when_no_key_is_configured(monkeypatch):
    """SANDBOX_RUNNER_API_KEY unset means this deployment hasn't opted
    in (most likely local dev running this service directly, outside
    Docker Compose) — must not lock every caller out by default."""
    monkeypatch.delenv("SANDBOX_RUNNER_API_KEY", raising=False)
    await require_api_key(authorization=None)  # must not raise


@pytest.mark.asyncio
async def test_require_api_key_rejects_a_missing_header_once_configured(monkeypatch):
    monkeypatch.setenv("SANDBOX_RUNNER_API_KEY", "secret-123")
    with pytest.raises(HTTPException) as exc_info:
        await require_api_key(authorization=None)
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_require_api_key_rejects_the_wrong_key(monkeypatch):
    monkeypatch.setenv("SANDBOX_RUNNER_API_KEY", "secret-123")
    with pytest.raises(HTTPException) as exc_info:
        await require_api_key(authorization="Bearer wrong-key")
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_require_api_key_rejects_a_non_bearer_header(monkeypatch):
    monkeypatch.setenv("SANDBOX_RUNNER_API_KEY", "secret-123")
    with pytest.raises(HTTPException):
        await require_api_key(authorization="secret-123")  # missing "Bearer " prefix


@pytest.mark.asyncio
async def test_require_api_key_accepts_the_correct_bearer_token(monkeypatch):
    monkeypatch.setenv("SANDBOX_RUNNER_API_KEY", "secret-123")
    await require_api_key(authorization="Bearer secret-123")  # must not raise
