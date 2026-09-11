"""HTTP request smuggling (§3) — TIMING-based detection only. This is
PortSwigger's own documented safe methodology for surfacing a *likely*
CL.TE/TE.CL desync without actually smuggling a second request onto the
wire (which would risk corrupting or intercepting another real user's
traffic on a shared/production system — exactly what §1.2's
safe-by-default guardrail forbids). httpx won't send genuinely
ambiguous Content-Length/Transfer-Encoding framing (it validates
headers), so this talks to a raw socket directly (app.agents.raw_http),
the same way http_client.probe_tls_version() already does for
TLS-version detection.

Two complementary probes are sent per host:
  - "te" variant: a Transfer-Encoding-chunked body that's deliberately
    left unterminated (no closing "0\\r\\n\\r\\n"), paired with a short
    Content-Length that only covers the first chunk. A backend that
    honors Transfer-Encoding here will block waiting for a terminating
    chunk that never arrives.
  - "cl" variant: a complete, correctly-terminated empty chunked body,
    paired with a Content-Length far larger than the bytes actually
    sent. A backend that honors Content-Length here will block waiting
    for bytes that never arrive.
A significant timing delta on either probe (re-verified once) reveals
which framing header this origin server actually honors when both are
present — real signal about desync risk if a front-end proxy in front
of it resolves the ambiguity the other way, but not a proof of an
actual working smuggling exploit.

A timing delta alone isn't independently provable the way a reflected
payload is (network jitter, a slow endpoint, or a WAF can all produce
the same signal), so per §2's Confirmed-Only Findings Policy this is
always queued as a ReviewCandidate — the same treatment
app.agents.deserialization gets for its passive signature match.

An LLM triage pass (added 2026-09, matching deserialization.py's) still
runs on every signal — not to promote it to a Finding (actually
smuggling a second request to prove the desync is exactly what §1.2's
safe-by-default guardrail forbids), but to replace the previously
templated `llm_reasoning` text with a real per-signal assessment (e.g.
weighing how large the timing delta was relative to the threshold, and
whether the target's likely under load in a way that could produce a
false positive) — same treatment as every other check, without
weakening the guarantee that a timing signal alone can never self-
confirm into a Finding.
"""

import asyncio
import uuid
from dataclasses import dataclass

import httpx

from app.agents.http_client import ScopedHttpClient
from app.agents.raw_http import send_raw
from app.ai.budget import BudgetExceededError, BudgetGuard, ProviderUnavailableError
from app.ai.prompts.loader import render_prompt
from app.ai.verdict import parse_verdict
from app.checks.loader import get_check
from app.checks.render import render_check_template
from app.models.review_candidate import ReviewCandidate

_CATALOG_FILE = "request_smuggling_catalog.yaml"
_BASELINE_TIMEOUT = 5.0
_PROBE_TIMEOUT = 3.0
_DELAY_THRESHOLD_SECONDS = 1.5  # probe must be at least this much slower than baseline


@dataclass
class SmugglingSignal:
    url: str
    variant: str  # "te" or "cl"
    delta_seconds: float


def _te_probe(host: str, path: str) -> bytes:
    # Content-Length: 4 covers exactly "1\r\nA" (one complete 1-byte
    # chunk's header+data, no terminator sent). A TE-based reader parses
    # that chunk fine and then blocks waiting for the next chunk-size
    # line; a CL-based reader stops after 4 bytes and responds
    # immediately.
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: 4\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
        f"1\r\nA"
    ).encode()


def _cl_probe(host: str, path: str) -> bytes:
    # Body is "0\r\n\r\n" (5 bytes) — a complete, immediately-terminated
    # empty chunked body. Content-Length: 50 claims far more bytes than
    # were sent. A CL-based reader blocks waiting for the other 45
    # bytes; a TE-based reader sees the chunked terminator and responds
    # immediately.
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: 50\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
        f"0\r\n\r\n"
    ).encode()


def _baseline_probe(host: str, path: str) -> bytes:
    return (
        f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    ).encode()


class RequestSmugglingAgent:
    """LLM triage refines llm_reasoning/llm_confidence on every signal
    (see module docstring) — but can never turn one into a Finding;
    that would require actually smuggling a request, which is
    deliberately never attempted here."""

    def __init__(
        self,
        client: ScopedHttpClient,
        *,
        scan_run_id: uuid.UUID,
        agent_job_id: uuid.UUID,
        db_session,
        budget_guard: BudgetGuard,
        ai_model: str,
    ):
        self._client = client
        self._scan_run_id = scan_run_id
        self._agent_job_id = agent_job_id
        self._session = db_session
        self._budget_guard = budget_guard
        self._ai_model = ai_model
        self.budget_exceeded = False
        self.budget_stop_reason: str | None = None

    async def run(self, endpoints: list[str]) -> list[ReviewCandidate]:
        candidates: list[ReviewCandidate] = []
        seen_hosts: set[tuple[str, int]] = set()
        for url in endpoints:
            parsed = httpx.URL(url)
            key = (parsed.host, parsed.port or (443 if parsed.scheme == "https" else 80))
            if key in seen_hosts:
                # This is host-parser behavior, not per-endpoint — one
                # result per distinct host:port is enough signal.
                continue
            seen_hosts.add(key)
            for signal in await self._check_host(url):
                candidates.append(await self._persist(signal))
        return candidates

    async def _check_host(self, url: str) -> list[SmugglingSignal]:
        parsed = httpx.URL(url)
        host = parsed.host
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_tls = parsed.scheme == "https"
        path = parsed.raw_path.decode() if parsed.raw_path else "/"

        try:
            _, baseline_elapsed = await asyncio.to_thread(
                send_raw, host, port, _baseline_probe(host, path), use_tls=use_tls, timeout=_BASELINE_TIMEOUT
            )
        except OSError:
            return []

        signals = []
        for variant, builder in (("te", _te_probe), ("cl", _cl_probe)):
            delta = await self._probe_variant(host, port, path, use_tls, baseline_elapsed, builder)
            if delta is None:
                continue
            # Re-verify once before queuing — reduces false positives
            # from one-off network jitter (§2 step 1's spirit, adapted
            # for a timing signal rather than a deterministic
            # re-execution).
            delta_again = await self._probe_variant(host, port, path, use_tls, baseline_elapsed, builder)
            if delta_again is None:
                continue
            signals.append(SmugglingSignal(url=url, variant=variant, delta_seconds=min(delta, delta_again)))
        return signals

    async def _probe_variant(self, host, port, path, use_tls, baseline_elapsed, builder) -> float | None:
        try:
            _, elapsed = await asyncio.to_thread(
                send_raw, host, port, builder(host, path), use_tls=use_tls, timeout=_PROBE_TIMEOUT
            )
        except OSError:
            return None
        delta = elapsed - baseline_elapsed
        if delta >= _DELAY_THRESHOLD_SECONDS:
            return delta
        return None

    async def _triage(self, signal: SmugglingSignal, variant_label: str, fallback_reasoning: str) -> tuple[str, str]:
        if self.budget_exceeded:
            return fallback_reasoning, "medium"
        messages = render_prompt(
            "deterministic_signal_triage",
            check_type=f"HTTP request smuggling ({variant_label})",
            url=signal.url,
            deterministic_signal=(
                f"A raw-socket {variant_label} probe was {signal.delta_seconds:.2f}s slower than "
                f"baseline (re-verified once; threshold is {_DELAY_THRESHOLD_SECONDS}s)"
            ),
            evidence_before="baseline: a plain GET request, timed for comparison",
            evidence_after=f"probe response was {signal.delta_seconds:.2f}s slower than that baseline",
        )
        try:
            response = await self._budget_guard.guarded_complete(messages, model=self._ai_model)
        except (BudgetExceededError, ProviderUnavailableError) as exc:
            self.budget_exceeded = True
            self.budget_stop_reason = (
                "provider_unavailable" if isinstance(exc, ProviderUnavailableError) else "budget_exceeded"
            )
            return fallback_reasoning, "medium"
        verdict = parse_verdict(response.content)
        if verdict is None:
            return fallback_reasoning, "medium"
        return verdict.reasoning, verdict.confidence

    async def _persist(self, signal: SmugglingSignal) -> ReviewCandidate:
        check_def = get_check("potential-http-request-smuggling", filename=_CATALOG_FILE)
        variant_label = (
            "Transfer-Encoding-prioritizing (unterminated chunked body)"
            if signal.variant == "te"
            else "Content-Length-prioritizing (oversized declared length)"
        )
        extra = {"variant": variant_label, "delta_seconds": f"{signal.delta_seconds:.2f}"}
        fallback_reasoning = render_check_template(check_def.technical_description, signal.url, extra)
        llm_reasoning, llm_confidence = await self._triage(signal, variant_label, fallback_reasoning)
        candidate = ReviewCandidate(
            scan_run_id=self._scan_run_id,
            agent_job_id=self._agent_job_id,
            check_type="potential-http-request-smuggling",
            title=f"{check_def.title} ({signal.url})",
            severity_guess=check_def.severity,
            affected_endpoint=signal.url,
            request_raw=f"(raw socket probe — {variant_label}) targeting {signal.url}",
            response_raw=f"response {signal.delta_seconds:.2f}s slower than baseline (threshold {_DELAY_THRESHOLD_SECONDS}s)",
            llm_reasoning=llm_reasoning,
            llm_confidence=llm_confidence,
            status="pending",
        )
        async with self._client.session_lock:
            self._session.add(candidate)
            await self._session.commit()
        return candidate
