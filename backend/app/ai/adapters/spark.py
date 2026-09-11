from decimal import Decimal
from typing import Any

import openai
from openai import AsyncAzureOpenAI

from app.ai.adapters.base import AgentResponse, AIProviderAdapter, Message

# ~4 chars/token is the standard rough estimate for English text with
# GPT-style tokenizers — used only as a fallback when Spark's response
# doesn't include real `usage` data (see complete()). Never exact, but
# far more honest for budget/usage visibility than a flat 0.
_CHARS_PER_TOKEN_ESTIMATE = 4


def _estimate_tokens(text: str) -> int:
    return max(1, len(text) // _CHARS_PER_TOKEN_ESTIMATE) if text else 0


class SparkAdapter(AIProviderAdapter):
    """S&P Global's internal Spark LLM gateway — an Azure-OpenAI-compatible
    API reachable at a fixed base URL + "app id" path segment, ported from
    the dast-automation reference implementation's SparkProvider.

    Empirically-observed quirk this adapter must reproduce: despite the
    openai SDK's AsyncAzureOpenAI offering a separate `azure_ad_token=`
    argument for OAuth bearer tokens (which would send a real
    `Authorization: Bearer ...` header), Spark ignores that header
    entirely and instead requires the token in a plain `api-key` header.
    The SDK also computes its own `Authorization: Bearer <api_key>`
    header from `api_key=` even though `azure_ad_token=` was not used, so
    this adapter doesn't rely on the SDK's automatic auth-header
    computation at all — `default_headers` forces the wire-correct
    `api-key` header explicitly.

    `app_id` — required for EVERY request, bearer token or API key
    alike (re-confirmed 2026-09 directly against sparkapi.spglobal.com
    — an earlier version of this docstring claimed bearer tokens didn't
    need one; that was wrong). It's sent both as a header and as a path
    segment (`{base_url}/v1/{app_id}`). Proof: `AsyncAzureOpenAI` always
    appends its own hardcoded `/openai/deployments/{model}/...` suffix
    onto `azure_endpoint`; omit `app_id` and the endpoint becomes
    `{base_url}/v1`, so Spark's gateway reads the SDK's literal
    "openai" segment out of the app_id slot and 401s with "app_id:
    openai is not valid" — a raw curl straight at Spark's bare
    `/v1/chat/completions` (no SDK) gets the identical treatment,
    just with "app_id: chat is not valid" instead, confirming Spark
    always reads *something* out of that path position, app_id or not.
    `app_id: str | None = None` stays typed as optional purely so a
    caller with no app_id at all still gets a clear "no app_id" 401
    instead of a `TypeError` — every real caller must supply one.

    `auth_type` otherwise only affects which Settings field the caller
    reads the token from (bearer_token vs. api_key) — the header shape
    for the token itself is identical either way.

    `fallback_token`, if given (only meaningful for api_key mode — a
    bearer token has nothing to fall back to), is a second, independent
    Spark API key. On an `AuthenticationError` (401/403-shaped) from the
    primary token, `complete()` retries exactly once with the fallback
    token before raising — a minimal version of dast-automation's
    primary/secondary key rotation, without that reference's DB-backed
    admin-rotation UI: here it's just "try the other key you gave us."
    """

    def __init__(
        self,
        token: str,
        *,
        base_url: str,
        api_version: str,
        app_id: str | None = None,
        fallback_token: str | None = None,
        http_client: Any = None,
    ):
        # http_client is test-only plumbing, same convention as
        # GenericOpenAIAdapter — lets tests inject an httpx2.MockTransport
        # instead of hitting a real Spark endpoint.
        self._base_url = base_url
        self._api_version = api_version
        self._app_id = app_id
        self._http_client = http_client
        self._fallback_token = fallback_token
        self._client = self._build_client(token)

    def _build_client(self, token: str) -> AsyncAzureOpenAI:
        endpoint = f"{self._base_url}/v1/{self._app_id}" if self._app_id else f"{self._base_url}/v1"
        headers = {"api-key": token}
        if self._app_id:
            headers["app_id"] = self._app_id
        return AsyncAzureOpenAI(
            azure_endpoint=endpoint,
            api_key=token,
            api_version=self._api_version,
            default_headers=headers,
            http_client=self._http_client,
            max_retries=0,
        )

    async def complete(
        self, messages: list[Message], *, model: str, max_tokens: int = 1024
    ) -> AgentResponse:
        try:
            response = await self._call(self._client, messages, model=model, max_tokens=max_tokens)
        except openai.AuthenticationError:
            if self._fallback_token is None:
                raise
            # One retry with the fallback key — and adopt it as the
            # active client going forward, so a scan's later calls don't
            # pay for this same failed-primary-key round trip every time.
            self._client = self._build_client(self._fallback_token)
            self._fallback_token = None
            response = await self._call(self._client, messages, model=model, max_tokens=max_tokens)

        content = response.choices[0].message.content or ""
        usage = response.usage
        if usage:
            input_tokens, output_tokens = usage.prompt_tokens, usage.completion_tokens
        else:
            # Empirically observed (2026-09): Spark's chat-completions
            # response consistently omits `usage` entirely — confirmed
            # across 20 real, successful calls in one scan, all with
            # zero recorded tokens despite genuine, correctly-parsed
            # responses. Rather than showing a flat, misleading "0
            # tokens" for every Spark-backed scan (which reads as "AI
            # didn't run" when it demonstrably did), fall back to a
            # rough ~4-chars-per-token estimate — the standard rule of
            # thumb for English text with GPT-style tokenizers. No
            # tiktoken dependency here: this is explicitly an estimate,
            # not a promise of exactness, same spirit as
            # estimate_cost()'s $0 (no public Spark pricing either).
            input_tokens = _estimate_tokens("".join(m.content for m in messages))
            output_tokens = _estimate_tokens(content)
        return AgentResponse(
            content=content,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            model=model,
        )

    @staticmethod
    async def _call(
        client: AsyncAzureOpenAI, messages: list[Message], *, model: str, max_tokens: int
    ) -> Any:
        return await client.chat.completions.create(
            model=model,
            max_tokens=max_tokens,
            messages=[{"role": m.role, "content": m.content} for m in messages],
            # See ClaudeAdapter.complete's identical rationale: every
            # prompt here is a structured classification, not open-ended
            # generation, so deterministic output is correct.
            temperature=0,
        )

    def estimate_cost(self, input_tokens: int, output_tokens: int, model: str) -> Decimal:
        # Spark is an internal gateway with no per-caller public pricing
        # catalog (unlike ClaudeAdapter/OpenAIAdapter's built-in tables) —
        # same $0 default as GenericOpenAIAdapter's self-hosted case.
        return Decimal(0)
