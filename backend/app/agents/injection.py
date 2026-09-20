import functools
import re
import uuid
from dataclasses import dataclass
from typing import Any, Awaitable, Callable
from urllib.parse import urlsplit, urlunsplit

import httpx

from app.agents.evidence import format_request_raw, format_response_raw
from app.agents.evidence_screenshot import capture_and_store_evidence_screenshot
from app.agents.http_client import AuthenticatedSession, ScopedHttpClient, ScopeViolationError
from app.agents.login import pick_best_session
from app.agents.probing import (
    BASELINE_VALUE,
    ProbeTarget,
    fetch_with_value,
    form_probe_targets,
    query_probe_targets,
)
from app.agents.recon import DiscoveredParameter, FormInfo
from app.ai.budget import BudgetExceededError, BudgetGuard, ProviderUnavailableError
from app.ai.prompt_truncation import truncate_pair_for_prompt
from app.ai.prompts.loader import render_prompt
from app.ai.verdict import extract_json_objects, parse_verdict
from app.models.finding import Evidence, Finding

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
    "path-traversal": {
        "title": "Path Traversal / Local File Inclusion",
        "owasp_2025_category": "A01 Broken Access Control",
        "cwe_id": "CWE-22",
        "severity": "High",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cvss_score": 7.5,
        "portswigger_reference_url": "https://portswigger.net/web-security/file-path-traversal",
        "plain_language_summary": (
            "This part of the application accepts attacker-controlled input "
            "that is used to build a file path without properly sanitizing it, "
            "which could let an attacker read arbitrary files on the server "
            "(such as system configuration or credential files) outside the "
            "intended directory."
        ),
        "remediation": (
            "Never build file paths directly from user input. Canonicalize the "
            "resolved path and verify it stays within an intended base "
            "directory (strict allow-list), or reference files indirectly "
            "(e.g. a database-backed file ID) instead of a raw path/filename."
        ),
    },
    "nosql-injection": {
        "title": "NoSQL Injection ($where / JavaScript context)",
        "owasp_2025_category": "A05 Injection",
        "cwe_id": "CWE-943",
        "severity": "High",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "cvss_score": 8.6,
        "portswigger_reference_url": "https://portswigger.net/web-security/nosql-injection",
        "plain_language_summary": (
            "This part of the application responds differently depending on an "
            "injected true/false NoSQL query condition, indicating attacker "
            "input reaches a MongoDB-style database query directly and could be "
            "used to bypass authentication or extract data the user shouldn't "
            "have access to."
        ),
        "remediation": (
            "Use a query builder / ODM that parameterizes values rather than "
            "string-concatenating user input into a query or $where clause, "
            "and reject non-scalar input where a scalar value is expected."
        ),
    },
}


ProbeFn = Callable[
    [ScopedHttpClient, ProbeTarget, "AuthenticatedSession | None"], Awaitable["InjectionCandidate | None"]
]


@dataclass
class InjectionCandidate:
    payload_type: str
    target: ProbeTarget
    payload: str
    deterministic_signal: str
    baseline_response: httpx.Response
    probe_response: httpx.Response
    probe_fn: ProbeFn
    # Set only by _probe_sqli_second_order — the page whose response
    # actually carried the true/false signal, when it's a different page
    # than the one the payload was submitted to. None means "same page",
    # the case every other probe function covers.
    consumer_url: str | None = None


_MAX_PARAMETERS_IN_PAYLOAD_PROMPT = 40


def _format_parameters_for_payload_prompt(parameters: list[DiscoveredParameter]) -> str:
    shown = parameters[:_MAX_PARAMETERS_IN_PAYLOAD_PROMPT]
    lines = [f"- {p.name} (sample value: {p.sample_value!r}) on {p.method} {p.url}" for p in shown]
    if len(parameters) > len(shown):
        lines.append(f"... and {len(parameters) - len(shown)} more, omitted for length")
    return "\n".join(lines) if lines else "(none discovered)"


def _format_tech_stack_for_payload_prompt(fingerprint: dict[str, Any] | None) -> str:
    if not fingerprint:
        return "(not determined)"
    parts = []
    for key in ("server_software", "backend_languages", "frontend_frameworks", "cms"):
        values = fingerprint.get(key) or []
        if values:
            parts.append(f"{key}: {', '.join(values)}")
    return "; ".join(parts) if parts else "(not determined)"


_MAX_AI_PAYLOADS = 5


def _parse_payload_suggestions(raw_content: str) -> list[str]:
    for data in extract_json_objects(raw_content):
        payloads = data.get("payloads")
        if isinstance(payloads, list):
            return [p for p in payloads if isinstance(p, str) and p][:_MAX_AI_PAYLOADS]
    return []


def _matches_sqli_error(text: str) -> bool:
    return any(p.search(text) for p in _SQLI_ERROR_PATTERNS)


async def _probe_sqli_error(
    client: ScopedHttpClient, target: ProbeTarget, session: AuthenticatedSession | None = None
) -> InjectionCandidate | None:
    baseline = await fetch_with_value(client, target, BASELINE_VALUE, session)
    payload = "'"
    probe = await fetch_with_value(client, target, payload, session)
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
    # Real gap found live: a raw "'" genuinely breaks a naively-built
    # SQL query (confirmed: SQLite raised OperationalError) but a
    # framework's generic unhandled-exception handler often returns a
    # bland "Internal Server Error" body with no recognizable SQL
    # wording at all — _matches_sqli_error, and therefore the check
    # above, never fires even though the injection is completely real.
    # A single quote flipping an otherwise-clean 2xx/4xx baseline into
    # an unhandled 5xx is itself the same signal sqlmap/Burp treat as
    # error-based evidence when the message body is suppressed — still
    # just a candidate for the LLM-triage/adversarial-validation gate
    # downstream, not a shortcut to a Finding.
    if probe.status_code >= 500 and baseline.status_code < 500:
        return InjectionCandidate(
            payload_type="sqli-error",
            target=target,
            payload=payload,
            deterministic_signal=(
                f"Injecting a single quote turned a clean {baseline.status_code} baseline "
                f"response into an unhandled {probe.status_code} server error, consistent with "
                "breaking a malformed SQL query even though no recognizable SQL error text "
                "appeared in the response body."
            ),
            baseline_response=baseline,
            probe_response=probe,
            probe_fn=_probe_sqli_error,
        )
    return None


async def _probe_sqli_error_ai(
    client: ScopedHttpClient,
    target: ProbeTarget,
    session: AuthenticatedSession | None = None,
    *,
    payloads: list[str],
) -> InjectionCandidate | None:
    """Same detection oracle as _probe_sqli_error (a SQL error string
    appearing in the probe response but not the baseline) — just tried
    against a batch of AI-suggested payload strings instead of the one
    fixed "'" (see InjectionAgent._generate_ai_payloads), informed by
    this scan's actual discovered parameter names/tech stack rather
    than a one-size-fits-all guess. Bound via functools.partial in
    InjectionAgent.run() so it still matches ProbeFn's signature.
    """
    baseline = await fetch_with_value(client, target, BASELINE_VALUE, session)
    for payload in payloads:
        probe = await fetch_with_value(client, target, payload, session)
        if _matches_sqli_error(probe.text) and not _matches_sqli_error(baseline.text):
            return InjectionCandidate(
                payload_type="sqli-error",
                target=target,
                payload=payload,
                deterministic_signal=(
                    "A SQL error string appeared in the probe response but not the baseline "
                    "response, using an AI-suggested payload tailored to this parameter/tech stack."
                ),
                baseline_response=baseline,
                probe_response=probe,
                probe_fn=functools.partial(_probe_sqli_error_ai, payloads=payloads),
            )
    return None


# Two distinct injection contexts, tried in order. The bare pair alone
# (found live to be the only pair ever tried) assumes the parameter
# sits at the very end of its quoted literal, e.g. `WHERE col =
# '{value}'` — real, but far from the only shape. A parameter wrapped
# in a LIKE search (`LIKE '%{value}%'`, one of the most common patterns
# for a "search" feature) or followed by more clause text leaves a
# trailing `%'`/other SQL after the injected value that neither the
# true nor the false bare payload ever neutralizes, so both produce the
# *same* (non-matching) result and the comparison sees no difference at
# all — a real SQLi missed outright. The `-- ` (SQL line-comment)
# variant comments out whatever the template puts after the injection
# point, so it still isolates the true/false condition even in that
# wrapped shape; it's tried second since it changes the query's meaning
# more than the bare pair does, so the bare pair stays preferred when
# it alone is sufficient to show a difference.
_SQLI_BOOLEAN_PAYLOAD_PAIRS = [
    ("verdikt1' OR '1'='1", "verdikt1' OR '1'='2"),
    ("verdikt1' OR '1'='1' -- ", "verdikt1' OR '1'='2' -- "),
]


async def _probe_sqli_boolean(
    client: ScopedHttpClient, target: ProbeTarget, session: AuthenticatedSession | None = None
) -> InjectionCandidate | None:
    for true_payload, false_payload in _SQLI_BOOLEAN_PAYLOAD_PAIRS:
        true_resp = await fetch_with_value(client, target, true_payload, session)
        false_resp = await fetch_with_value(client, target, false_payload, session)
        if true_resp.status_code != false_resp.status_code:
            continue
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


def _consumer_page_url(url: str) -> str | None:
    """The directory URL one level up from a page's own filename — e.g.
    ".../vulnerabilities/sqli/session-input.php" -> ".../vulnerabilities/sqli/".
    Returns None for a URL that's already a directory index (nothing
    shallower to distinguish from itself).

    This is the "consumer page" _probe_sqli_second_order checks instead
    of the target's own response — see that function's docstring for why
    a same-directory index page is a reasonable, generalizable guess for
    where a session-scoped input actually gets used, not a DVWA-specific
    hardcode.
    """
    parsed = urlsplit(url)
    if not parsed.path or parsed.path.endswith("/"):
        return None
    directory = parsed.path.rsplit("/", 1)[0] + "/"
    return urlunsplit((parsed.scheme, parsed.netloc, directory, "", ""))


async def _probe_sqli_second_order(
    client: ScopedHttpClient, target: ProbeTarget, session: AuthenticatedSession | None = None
) -> InjectionCandidate | None:
    """Second-order (a.k.a. stored) SQL injection: some forms don't query
    a database themselves at all — they just persist a value (into a
    session variable, a database row, a config file) that a DIFFERENT
    page's query uses later. _probe_sqli_boolean and _probe_sqli_error
    are both structurally blind to this: they only ever compare the
    immediate response to the same request that carried the payload, so
    a form like this always looks identical regardless of what was
    submitted, and the actual vulnerability goes completely unreported.

    A real, live-found example (§14): DVWA's own SQL Injection page at
    "High" difficulty replaces its normal <form> with a link that opens
    a popup (now itself discoverable — app.agents.recon's onclick-link
    support) whose only job is `$_SESSION['id'] = $_POST['id']`; the
    actual unescaped `WHERE user_id = '$id'` query — just as injectable
    as at "Low" — runs on a completely different page the next time it's
    loaded. This targets the one directory-relative page most likely to
    be that "different page": the target's own containing directory's
    index (`_consumer_page_url`) — cheap to guess generically (no
    DVWA-specific path hardcoded) since a session-scoped helper endpoint
    overwhelmingly lives right next to the page that actually uses it.

    POST-only: a GET parameter's own page already gets tested directly
    by every other probe, so this would just be redundant work for it.
    """
    if target.method != "POST":
        return None
    consumer_url = _consumer_page_url(target.url)
    if consumer_url is None or consumer_url == target.url:
        return None

    for true_payload, false_payload in _SQLI_BOOLEAN_PAYLOAD_PAIRS:
        await fetch_with_value(client, target, true_payload, session)
        true_resp = await client.get(consumer_url, session=session)
        await fetch_with_value(client, target, false_payload, session)
        false_resp = await client.get(consumer_url, session=session)
        if true_resp.status_code != false_resp.status_code:
            continue
        len_true, len_false = len(true_resp.text), len(false_resp.text)
        if abs(len_true - len_false) > max(20, 0.05 * max(len_true, len_false, 1)):
            return InjectionCandidate(
                payload_type="sqli-boolean",
                target=target,
                payload=true_payload,
                deterministic_signal=(
                    f"After submitting this form, {consumer_url}'s response length differs "
                    f"meaningfully between a true condition ({len_true} bytes) and a false "
                    f"condition ({len_false} bytes) — consistent with the submitted value "
                    "reaching an unescaped SQL query on a different page than the one it was "
                    "submitted to."
                ),
                baseline_response=false_resp,
                probe_response=true_resp,
                probe_fn=_probe_sqli_second_order,
                consumer_url=consumer_url,
            )
    return None


async def _probe_command_injection(
    client: ScopedHttpClient, target: ProbeTarget, session: AuthenticatedSession | None = None
) -> InjectionCandidate | None:
    marker = f"VERDIKT{uuid.uuid4().hex[:8]}"
    baseline = await fetch_with_value(client, target, BASELINE_VALUE, session)
    # The first three are the "obvious" separators — but a blacklist-style
    # filter that strips exact substrings like "; ", "| " (with a
    # trailing space) or "&" entirely defeats all three while leaving the
    # underlying shell call just as injectable (verified live: DVWA High's
    # exec filter strips '||', '&', ';', '| ' (pipe+space), '-', '$', '(',
    # ')', '`' — notably NOT a bare '|' with no trailing space, and not a
    # literal newline). The last three exist specifically to survive that
    # class of filter, each via a different separator a naive blacklist
    # commonly misses:
    for template in (
        "; echo {marker}",
        "| echo {marker}",
        "`echo {marker}`",
        "|echo {marker}",  # pipe, no trailing space — survives a "| " (pipe+space) blacklist entry
        "\necho {marker}",  # a raw newline separates shell commands exactly like ';' does
        "&& echo {marker}",  # a filter that blocks lone ';'/'|' commonly leaves '&&' untouched
    ):
        payload = template.format(marker=marker)
        probe = await fetch_with_value(client, target, payload, session)
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


async def _probe_ssti(
    client: ScopedHttpClient, target: ProbeTarget, session: AuthenticatedSession | None = None
) -> InjectionCandidate | None:
    baseline = await fetch_with_value(client, target, BASELINE_VALUE, session)
    if not _is_template_renderable(baseline):
        return None
    for payload in ("{{7*7}}", "${7*7}"):
        probe = await fetch_with_value(client, target, payload, session)
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


_PATH_TRAVERSAL_MARKER_RE = re.compile(r"root:.*:0:0:", re.IGNORECASE)


async def _probe_path_traversal(
    client: ScopedHttpClient, target: ProbeTarget, session: AuthenticatedSession | None = None
) -> InjectionCandidate | None:
    baseline = await fetch_with_value(client, target, BASELINE_VALUE, session)
    for payload in ("../../../../../../../../etc/passwd", "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd"):
        probe = await fetch_with_value(client, target, payload, session)
        if _PATH_TRAVERSAL_MARKER_RE.search(probe.text) and not _PATH_TRAVERSAL_MARKER_RE.search(
            baseline.text
        ):
            return InjectionCandidate(
                payload_type="path-traversal",
                target=target,
                payload=payload,
                deterministic_signal="The contents of /etc/passwd (a 'root:...:0:0:' entry) appeared "
                "in the probe response only, consistent with unsanitized path traversal reaching "
                "the filesystem.",
                baseline_response=baseline,
                probe_response=probe,
                probe_fn=_probe_path_traversal,
            )
    return None


async def _probe_nosqli(
    client: ScopedHttpClient, target: ProbeTarget, session: AuthenticatedSession | None = None
) -> InjectionCandidate | None:
    """Boolean-differential NoSQL injection via MongoDB's $where JS
    evaluation context — same length-differential mechanism as
    _probe_sqli_boolean, just with a payload pair meaningful to a
    string-concatenated $where/JS query instead of a SQL one.
    """
    true_payload = "';return true;var x='"
    false_payload = "';return false;var x='"
    true_resp = await fetch_with_value(client, target, true_payload, session)
    false_resp = await fetch_with_value(client, target, false_payload, session)
    if true_resp.status_code != false_resp.status_code:
        return None
    len_true, len_false = len(true_resp.text), len(false_resp.text)
    if abs(len_true - len_false) > max(20, 0.05 * max(len_true, len_false, 1)):
        return InjectionCandidate(
            payload_type="nosql-injection",
            target=target,
            payload=true_payload,
            deterministic_signal=(
                f"Response length differs meaningfully between a NoSQL $where "
                f"true-condition payload ({len_true} bytes) and a false-condition payload "
                f"({len_false} bytes) injected into the same parameter, consistent with "
                "unsanitized input reaching a MongoDB $where/JS query context."
            ),
            baseline_response=false_resp,
            probe_response=true_resp,
            probe_fn=_probe_nosqli,
        )
    return None


_PROBE_FNS: list[ProbeFn] = [
    _probe_sqli_error,
    _probe_sqli_boolean,
    _probe_sqli_second_order,
    _probe_command_injection,
    _probe_ssti,
    _probe_path_traversal,
    _probe_nosqli,
]


class InjectionAgent:
    """Deterministic probe battery (error/boolean SQLi, benign-marker
    command injection, SSTI) -> LLM triage -> deterministic re-execution
    (§2 step 1) -> adversarial LLM validation (§2 step 3) -> Finding.
    Server-side and re-fetchable, so — unlike XSS — these can become real
    ai_confirmed Findings without browser proof.

    Also generates one extra batch of AI-suggested SQLi-error payloads
    per run() (not per parameter/target — a per-parameter LLM call would
    burn through the scan-wide budget long before later parameters are
    ever reached), informed
    by this scan's actual discovered parameter names and tech-stack
    fingerprint, supplementing (never replacing) the fixed payload
    battery above. A wrong/ineffective suggestion just never triggers
    the same deterministic error-string signal every other payload is
    judged by — no separate trust path, no separate risk.
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
        self.budget_stop_reason: str | None = None
        self._auth_session: AuthenticatedSession | None = None

    async def run(
        self,
        parameters: list[DiscoveredParameter],
        forms: list[FormInfo],
        sessions: dict[uuid.UUID, AuthenticatedSession] | None = None,
        tech_stack_fingerprint: dict[str, Any] | None = None,
    ) -> list[Finding]:
        # A real, significant bug found live against DVWA: these probes
        # never carried any session at all before this fix, silently
        # running fully unauthenticated against every target — any
        # login-gated page was structurally unreachable, regardless of
        # how vulnerable it actually was. One representative identity
        # (not every session — CSRF-style multi-identity iteration would
        # multiply probe volume, and AI triage cost, by the number of
        # credential sets for no real gain here) is enough for probes
        # to actually reach authenticated surface at all.
        self._auth_session = pick_best_session(sessions)
        targets = query_probe_targets(parameters) + form_probe_targets(forms)
        findings: list[Finding] = []

        probe_fns = list(_PROBE_FNS)
        ai_payloads = await self._generate_ai_payloads(parameters, tech_stack_fingerprint)
        if ai_payloads:
            probe_fns.append(functools.partial(_probe_sqli_error_ai, payloads=ai_payloads))

        for target in targets:
            if self.budget_exceeded:
                break
            for probe_fn in probe_fns:
                try:
                    candidate = await probe_fn(self._client, target, self._auth_session)
                except (ScopeViolationError, httpx.HTTPError):
                    continue
                if candidate is None:
                    continue
                try:
                    finding = await self._triage_and_confirm(candidate)
                except (BudgetExceededError, ProviderUnavailableError) as exc:
                    self.budget_exceeded = True
                    self.budget_stop_reason = (
                        "provider_unavailable" if isinstance(exc, ProviderUnavailableError) else "budget_exceeded"
                    )
                    break
                if finding is not None:
                    findings.append(finding)

        return findings

    async def _generate_ai_payloads(
        self, parameters: list[DiscoveredParameter], tech_stack_fingerprint: dict[str, Any] | None
    ) -> list[str]:
        if not parameters or self.budget_exceeded:
            # Nothing to inform a suggestion with, or no budget left to
            # spend on one — same pre-filter discipline as
            # business_logic_planner's empty-site-map check.
            return []
        messages = render_prompt(
            "injection_payload_suggestions",
            parameters=_format_parameters_for_payload_prompt(parameters),
            tech_stack=_format_tech_stack_for_payload_prompt(tech_stack_fingerprint),
        )
        try:
            response = await self._budget_guard.guarded_complete(messages, model=self._ai_model, max_tokens=512)
        except (BudgetExceededError, ProviderUnavailableError) as exc:
            self.budget_exceeded = True
            self.budget_stop_reason = (
                "provider_unavailable" if isinstance(exc, ProviderUnavailableError) else "budget_exceeded"
            )
            return []
        return _parse_payload_suggestions(response.content)

    async def _triage_and_confirm(self, candidate: InjectionCandidate) -> Finding | None:
        baseline_text, probe_text = truncate_pair_for_prompt(
            candidate.baseline_response.text, candidate.probe_response.text
        )
        messages = render_prompt(
            "injection_triage",
            payload_type=candidate.payload_type,
            url=candidate.target.url,
            parameter=candidate.target.param_name,
            payload=candidate.payload,
            deterministic_signal=candidate.deterministic_signal,
            baseline_response=baseline_text,
            probe_response=probe_text,
        )
        response = await self._budget_guard.guarded_complete(messages, model=self._ai_model)
        verdict = parse_verdict(response.content)
        if verdict is None or not verdict.vulnerable:
            return None

        # §2 step 1: deterministic re-execution — re-run the exact same
        # probe fresh; if it doesn't reproduce, discard silently.
        reproduced = await candidate.probe_fn(self._client, candidate.target, self._auth_session)
        if reproduced is None:
            return None

        reproduced_baseline_text, reproduced_probe_text = truncate_pair_for_prompt(
            reproduced.baseline_response.text, reproduced.probe_response.text
        )
        validation_messages = render_prompt(
            "injection_validation",
            payload_type=reproduced.payload_type,
            url=reproduced.target.url,
            parameter=reproduced.target.param_name,
            payload=reproduced.payload,
            prior_reasoning=verdict.reasoning,
            baseline_response=reproduced_baseline_text,
            probe_response=reproduced_probe_text,
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
            affected_endpoints=(
                [candidate.target.url, candidate.consumer_url]
                if candidate.consumer_url
                else [candidate.target.url]
            ),
            plain_language_summary=meta["plain_language_summary"],
            technical_description=(
                f"{candidate.deterministic_signal} An independent adversarial "
                f"review attempted to disprove this and could not: "
                f"{validation_verdict.reasoning}"
            ),
            steps_to_reproduce=(
                [
                    f"1. Submit a {candidate.target.method} request to {candidate.target.url} with "
                    f"parameter '{candidate.target.param_name}' set to an innocuous baseline value, "
                    f"then load {candidate.consumer_url}.",
                    f"2. Submit the same request with '{candidate.target.param_name}' set to: "
                    f"{candidate.payload} — then load {candidate.consumer_url} again.",
                    f"3. Compare the two loads of {candidate.consumer_url}: {candidate.deterministic_signal}",
                ]
                if candidate.consumer_url
                else [
                    f"1. Send a {candidate.target.method} request to {candidate.target.url} with "
                    f"parameter '{candidate.target.param_name}' set to an innocuous baseline value.",
                    f"2. Send the same request with '{candidate.target.param_name}' set to: "
                    f"{candidate.payload}",
                    f"3. Compare the two responses: {candidate.deterministic_signal}",
                ]
            ),
            remediation=meta["remediation"],
            references=[meta["portswigger_reference_url"], f"https://cwe.mitre.org/data/definitions/"
            f"{meta['cwe_id'].split('-')[1]}.html"],
            confirmation_status="ai_confirmed",
        )
        request_raw = format_request_raw(candidate.probe_response)
        response_raw = format_response_raw(candidate.probe_response)
        screenshot_refs = await capture_and_store_evidence_screenshot(
            scan_run_id=self._scan_run_id,
            check_id=finding.check_id,
            title=finding.title,
            request_raw=request_raw,
            response_raw=response_raw,
        )
        async with self._client.session_lock:
            self._session.add(finding)
            await self._session.flush()

            self._session.add(
                Evidence(
                    finding_id=finding.id,
                    request_raw=request_raw,
                    response_raw=response_raw,
                    payload=candidate.payload,
                    screenshot_refs=screenshot_refs,
                )
            )
            await self._session.commit()
        return finding
