import re
import uuid
from dataclasses import dataclass
from typing import Awaitable, Callable

import httpx

from app.agents.evidence import format_request_raw, format_response_raw
from app.agents.http_client import ScopedHttpClient, ScopeViolationError
from app.agents.probing import (
    BASELINE_VALUE,
    ProbeTarget,
    fetch_with_value,
    form_probe_targets,
    query_probe_targets,
)
from app.agents.recon import DiscoveredParameter, FormInfo
from app.ai.budget import BudgetExceededError, BudgetGuard
from app.ai.prompts.loader import render_prompt
from app.ai.verdict import parse_verdict
from app.models.finding import Evidence, Finding

_TRUNCATE = 2000

_SQLI_ERROR_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"you have an error in your sql syntax",
        r"warning:\s*mysql_",
        r"unclosed quotation mark",
        r"quoted string not properly terminated",
        r"sqlstate\[",
        r"pg_query\(\)",
        r"sqlite3?::",
        r"ORA-\d{5}",
        r"System\.Data\.SqlClient",
        r"PostgreSQL.*ERROR",
        r"ODBC SQL Server Driver",
    ]
]

_INJECTION_METADATA = {
    "sqli-error": {
        "title": "SQL Injection (error-based)",
        "owasp_2025_category": "A05 Injection",
        "cwe_id": "CWE-89",
        "severity": "Critical",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_score": 9.8,
        "portswigger_reference_url": "https://portswigger.net/web-security/sql-injection",
        "plain_language_summary": (
            "This part of the application appears to accept attacker-controlled "
            "input that gets interpreted as part of a database query, which could "
            "let an attacker read, modify, or delete data they should never have "
            "access to."
        ),
        "remediation": (
            "Use parameterized queries / prepared statements for all database "
            "access; never build SQL by string-concatenating user input."
        ),
    },
    "sqli-boolean": {
        "title": "SQL Injection (boolean-based blind)",
        "owasp_2025_category": "A05 Injection",
        "cwe_id": "CWE-89",
        "severity": "High",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "cvss_score": 8.6,
        "portswigger_reference_url": "https://portswigger.net/web-security/sql-injection/blind",
        "plain_language_summary": (
            "This part of the application responds differently depending on "
            "whether an injected true/false condition is true or false, "
            "indicating attacker input reaches a database query directly."
        ),
        "remediation": (
            "Use parameterized queries / prepared statements for all database "
            "access; never build SQL by string-concatenating user input."
        ),
    },
    "command-injection": {
        "title": "OS Command Injection",
        "owasp_2025_category": "A05 Injection",
        "cwe_id": "CWE-78",
        "severity": "Critical",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_score": 9.8,
        "portswigger_reference_url": "https://portswigger.net/web-security/os-command-injection",
        "plain_language_summary": (
            "This part of the application appears to pass attacker-controlled "
            "input to a system shell command, which could let an attacker run "
            "arbitrary commands on the server."
        ),
        "remediation": (
            "Avoid invoking shell commands with user input; if unavoidable, use "
            "a strict allow-list and a non-shell exec API that does not "
            "interpret shell metacharacters."
        ),
    },
    "ssti": {
        "title": "Server-Side Template Injection",
        "owasp_2025_category": "A05 Injection",
        "cwe_id": "CWE-1336",
        "severity": "Critical",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_score": 9.8,
        "portswigger_reference_url": "https://portswigger.net/web-security/server-side-template-injection",
        "plain_language_summary": (
            "This part of the application appears to evaluate attacker-controlled "
            "input as template syntax, which can often be escalated to running "
            "arbitrary code on the server."
        ),
        "remediation": (
            "Never render user input as a template; if user content must appear "
            "in output, treat it strictly as data, not template source."
        ),
    },
}


ProbeFn = Callable[[ScopedHttpClient, ProbeTarget], Awaitable["InjectionCandidate | None"]]


@dataclass
class InjectionCandidate:
    payload_type: str
    target: ProbeTarget
    payload: str
    deterministic_signal: str
    baseline_response: httpx.Response
    probe_response: httpx.Response
    probe_fn: ProbeFn


def _matches_sqli_error(text: str) -> bool:
    return any(p.search(text) for p in _SQLI_ERROR_PATTERNS)


async def _probe_sqli_error(client: ScopedHttpClient, target: ProbeTarget) -> InjectionCandidate | None:
    baseline = await fetch_with_value(client, target, BASELINE_VALUE)
    payload = "'"
    probe = await fetch_with_value(client, target, payload)
    if _matches_sqli_error(probe.text) and not _matches_sqli_error(baseline.text):
        return InjectionCandidate(
            payload_type="sqli-error",
            target=target,
            payload=payload,
            deterministic_signal="A SQL error string appeared in the probe response but not the baseline response.",
            baseline_response=baseline,
            probe_response=probe,
            probe_fn=_probe_sqli_error,
        )
    return None


async def _probe_sqli_boolean(client: ScopedHttpClient, target: ProbeTarget) -> InjectionCandidate | None:
    true_payload = "verdikt1' OR '1'='1"
    false_payload = "verdikt1' OR '1'='2"
    true_resp = await fetch_with_value(client, target, true_payload)
    false_resp = await fetch_with_value(client, target, false_payload)
    if true_resp.status_code != false_resp.status_code:
        return None
    len_true, len_false = len(true_resp.text), len(false_resp.text)
    if abs(len_true - len_false) > max(20, 0.05 * max(len_true, len_false, 1)):
        return InjectionCandidate(
            payload_type="sqli-boolean",
            target=target,
            payload=true_payload,
            deterministic_signal=(
                f"Response length differs meaningfully between a true condition "
                f"({len_true} bytes) and a false condition ({len_false} bytes) "
                f"injected into the same parameter."
            ),
            baseline_response=false_resp,
            probe_response=true_resp,
            probe_fn=_probe_sqli_boolean,
        )
    return None


async def _probe_command_injection(client: ScopedHttpClient, target: ProbeTarget) -> InjectionCandidate | None:
    marker = f"VERDIKT{uuid.uuid4().hex[:8]}"
    baseline = await fetch_with_value(client, target, BASELINE_VALUE)
    for template in ("; echo {marker}", "| echo {marker}", "`echo {marker}`"):
        payload = template.format(marker=marker)
        probe = await fetch_with_value(client, target, payload)
        if marker in probe.text and marker not in baseline.text:
            return InjectionCandidate(
                payload_type="command-injection",
                target=target,
                payload=payload,
                deterministic_signal=f"Marker '{marker}' echoed back in the probe response only, "
                "consistent with shell command execution.",
                baseline_response=baseline,
                probe_response=probe,
                probe_fn=_probe_command_injection,
            )
    return None


def _is_template_renderable(response: httpx.Response) -> bool:
    """§10 smart scan: SSTI requires the payload to be evaluated as
    template syntax in server-rendered output. A response whose
    Content-Type is a data format (JSON/XML/etc., not HTML/plain text)
    is very unlikely to be passing through a server-side template engine
    in typical architectures — a pure JSON API endpoint just doesn't have
    a template rendering step in the response path. Skipping SSTI probing
    there saves two requests and a possible LLM triage call per target on
    JSON-API-heavy applications, without weakening coverage on the actual
    template-rendered surface (SQLi/command-injection aren't gated this
    way — they apply broadly regardless of response format).
    """
    content_type = response.headers.get("content-type", "").lower()
    return "json" not in content_type and "xml" not in content_type


async def _probe_ssti(client: ScopedHttpClient, target: ProbeTarget) -> InjectionCandidate | None:
    baseline = await fetch_with_value(client, target, BASELINE_VALUE)
    if not _is_template_renderable(baseline):
        return None
    for payload in ("{{7*7}}", "${7*7}"):
        probe = await fetch_with_value(client, target, payload)
        if "49" in probe.text and "49" not in baseline.text:
            return InjectionCandidate(
                payload_type="ssti",
                target=target,
                payload=payload,
                deterministic_signal="The template expression's evaluated result (49) appeared in the "
                "probe response only, consistent with server-side template evaluation.",
                baseline_response=baseline,
                probe_response=probe,
                probe_fn=_probe_ssti,
            )
    return None


_PROBE_FNS: list[ProbeFn] = [_probe_sqli_error, _probe_sqli_boolean, _probe_command_injection, _probe_ssti]


class InjectionAgent:
    """Deterministic probe battery (error/boolean SQLi, benign-marker
    command injection, SSTI) -> LLM triage -> deterministic re-execution
    (§2 step 1) -> adversarial LLM validation (§2 step 3) -> Finding.
    Server-side and re-fetchable, so — unlike XSS — these can become real
    ai_confirmed Findings without browser proof.
    """

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
        # Set when the §10.5 budget cap is hit mid-run. run() still returns
        # whatever it found before that point rather than losing partial
        # results — the caller (graph node) checks this flag to record the
        # AgentJob as "skipped" (budget) vs "completed".
        self.budget_exceeded = False

    async def run(
        self, parameters: list[DiscoveredParameter], forms: list[FormInfo]
    ) -> list[Finding]:
        targets = query_probe_targets(parameters) + form_probe_targets(forms)
        findings: list[Finding] = []

        for target in targets:
            if self.budget_exceeded:
                break
            for probe_fn in _PROBE_FNS:
                try:
                    candidate = await probe_fn(self._client, target)
                except (ScopeViolationError, httpx.HTTPError):
                    continue
                if candidate is None:
                    continue
                try:
                    finding = await self._triage_and_confirm(candidate)
                except BudgetExceededError:
                    self.budget_exceeded = True
                    break
                if finding is not None:
                    findings.append(finding)

        return findings

    async def _triage_and_confirm(self, candidate: InjectionCandidate) -> Finding | None:
        messages = render_prompt(
            "injection_triage",
            payload_type=candidate.payload_type,
            url=candidate.target.url,
            parameter=candidate.target.param_name,
            payload=candidate.payload,
            deterministic_signal=candidate.deterministic_signal,
            baseline_response=candidate.baseline_response.text[:_TRUNCATE],
            probe_response=candidate.probe_response.text[:_TRUNCATE],
        )
        response = await self._budget_guard.guarded_complete(messages, model=self._ai_model)
        verdict = parse_verdict(response.content)
        if verdict is None or not verdict.vulnerable:
            return None

        # §2 step 1: deterministic re-execution — re-run the exact same
        # probe fresh; if it doesn't reproduce, discard silently.
        reproduced = await candidate.probe_fn(self._client, candidate.target)
        if reproduced is None:
            return None

        validation_messages = render_prompt(
            "injection_validation",
            payload_type=reproduced.payload_type,
            url=reproduced.target.url,
            parameter=reproduced.target.param_name,
            payload=reproduced.payload,
            prior_reasoning=verdict.reasoning,
            baseline_response=reproduced.baseline_response.text[:_TRUNCATE],
            probe_response=reproduced.probe_response.text[:_TRUNCATE],
        )
        validation_response = await self._budget_guard.guarded_complete(
            validation_messages, model=self._ai_model
        )
        validation_verdict = parse_verdict(validation_response.content)
        if validation_verdict is None or not validation_verdict.vulnerable:
            return None

        return await self._persist(reproduced, verdict, validation_verdict)

    async def _persist(self, candidate: InjectionCandidate, verdict, validation_verdict) -> Finding:
        meta = _INJECTION_METADATA[candidate.payload_type]
        finding = Finding(
            scan_run_id=self._scan_run_id,
            agent_job_id=self._agent_job_id,
            check_id=candidate.payload_type,
            title=meta["title"],
            severity=meta["severity"],
            owasp_2025_category=meta["owasp_2025_category"],
            cwe_id=meta["cwe_id"],
            portswigger_reference_url=meta["portswigger_reference_url"],
            cvss_vector=meta["cvss_vector"],
            cvss_score=meta["cvss_score"],
            affected_endpoints=[candidate.target.url],
            plain_language_summary=meta["plain_language_summary"],
            technical_description=(
                f"{candidate.deterministic_signal} An independent adversarial "
                f"review attempted to disprove this and could not: "
                f"{validation_verdict.reasoning}"
            ),
            steps_to_reproduce=[
                f"1. Send a {candidate.target.method} request to {candidate.target.url} with "
                f"parameter '{candidate.target.param_name}' set to an innocuous baseline value.",
                f"2. Send the same request with '{candidate.target.param_name}' set to: "
                f"{candidate.payload}",
                f"3. Compare the two responses: {candidate.deterministic_signal}",
            ],
            remediation=meta["remediation"],
            references=[meta["portswigger_reference_url"], f"https://cwe.mitre.org/data/definitions/"
            f"{meta['cwe_id'].split('-')[1]}.html"],
            confirmation_status="ai_confirmed",
        )
        async with self._client.session_lock:
            self._session.add(finding)
            await self._session.flush()

            self._session.add(
                Evidence(
                    finding_id=finding.id,
                    request_raw=format_request_raw(candidate.probe_response),
                    response_raw=format_response_raw(candidate.probe_response),
                )
            )
            await self._session.commit()
        return finding
