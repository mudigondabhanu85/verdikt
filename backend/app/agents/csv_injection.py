"""CSV/Formula Injection (ported from a sibling DAST project) — submit a
value starting with "=" through a form, then check other discovered
pages/endpoints for it round-tripping completely unescaped. Same overall
shape as app.agents.stored_xss (submit via a form, look for it again on
OTHER pages, re-confirm with a fresh marker before persisting), but the
oracle here is a plain-text substring check on the raw HTTP response —
"is this exact string still there, unescaped" needs no headless browser
at all, unlike stored XSS's "did a <script> tag actually execute".

The substring check is deliberately stricter than "marker present
anywhere in the body": a value beginning with "=" that survives with a
single leading quote/tab/CR in front of it is the textbook OWASP
mitigation working correctly, not a vulnerability — reporting that as a
finding would be a straightforward, easily-avoided false positive on a
genuinely safe app. Only a marker whose leading "=" has nothing
neutralizing immediately in front of it counts as confirmed.

Full end-to-end proof (a real downloadable CSV containing the live
payload) needs an actual export feature, which recon has no reliable way
to discover generically — "Export" buttons are exactly the kind of
same-page JS-driven action a static crawl doesn't see as its own link.
Rather than skip the check entirely or silently claim more than was
verified, this best-effort-probes a handful of conventional export URL
shapes and is explicit in the finding about which case it landed in.
"""

import uuid
from urllib.parse import urlencode, urlsplit

import httpx

from app.agents.evidence import format_request_raw, format_response_raw
from app.agents.http_client import AuthenticatedSession, ScopedHttpClient, ScopeViolationError
from app.agents.login import _live_field_values, pick_best_session
from app.agents.recon import FormInfo
from app.checks.loader import get_check
from app.checks.render import render_check_template
from app.models.finding import Evidence, Finding

_CATALOG_FILE = "csv_injection_catalog.yaml"
_MAX_REVISIT_PAGES = 10
_BASELINE_FIELD_VALUE = "verdikt1"

# The standard OWASP-documented mitigation for this exact class of bug:
# prefix a value that would otherwise start with a formula-triggering
# character with one of these before storing/exporting it. A marker
# whose "=" is immediately preceded by any of these is evidence the
# mitigation is *working*, not evidence of a vulnerability.
_NEUTRALIZING_PREFIXES = ("'", "\t", "\r", "\n")

# A handful of conventional shapes real apps use for a CSV/spreadsheet
# export feature — deliberately small (§1.2 safe-by-default: this is a
# best-effort guess, not a directory brute-force) and read-only (GET
# only, never guessed as a form target).
_EXPORT_PATH_SHAPES = (
    "/export",
    "/export/csv",
    "/export.csv",
    "/api/export",
    "/download/csv",
    "/reports/export",
)


def _marker() -> str:
    return f"verdikt_csv_{uuid.uuid4().hex[:10]}"


def _payload_for(marker: str) -> str:
    return f"={marker}"


def _testable_fields(form: FormInfo) -> list:
    return [f for f in form.fields if f.type not in ("hidden", "submit", "button") and f.name]


def _build_payload_fields(form: FormInfo, target_field: str, payload: str) -> dict[str, str]:
    return {
        field.name: payload if field.name == target_field else _BASELINE_FIELD_VALUE
        for field in _testable_fields(form)
    }


def _round_trips_unescaped(text: str, marker: str) -> bool:
    """True only if "={marker}" appears literally in `text` with nothing
    neutralizing immediately before the "=". A bare substring match on
    the marker alone (without also requiring the leading "=" and
    checking what precedes it) would flag an app that correctly
    quote-prefixes the value as if it hadn't — exactly the false
    positive this whole check exists to avoid.
    """
    needle = _payload_for(marker)
    index = text.find(needle)
    if index == -1:
        return False
    if index == 0:
        return True
    return text[index - 1] not in _NEUTRALIZING_PREFIXES


class CsvInjectionAgent:
    def __init__(
        self,
        client: ScopedHttpClient,
        *,
        scan_run_id: uuid.UUID,
        agent_job_id: uuid.UUID,
        db_session,
    ):
        self._client = client
        self._scan_run_id = scan_run_id
        self._agent_job_id = agent_job_id
        self._session = db_session
        self._auth_session: AuthenticatedSession | None = None

    async def run(
        self,
        forms: list[FormInfo],
        endpoints: list[str],
        sessions: dict[uuid.UUID, AuthenticatedSession] | None = None,
    ) -> list[Finding]:
        # Same one-representative-identity reasoning as StoredXssAgent —
        # this is proving a storage/export precondition exists at all,
        # not testing per-credential behavior differences.
        self._auth_session = pick_best_session(sessions)
        findings: list[Finding] = []
        for form in forms:
            if form.method != "POST":
                continue
            candidates = list(dict.fromkeys([form.action_url, *endpoints]))[:_MAX_REVISIT_PAGES]
            for field in _testable_fields(form):
                finding = await self._check_form(form, field.name, candidates)
                if finding is not None:
                    findings.append(finding)
        return findings

    async def _submit(self, form: FormInfo, target_field: str, payload: str) -> httpx.Response | None:
        fields = _build_payload_fields(form, target_field, payload)
        other_names = {f.name for f in form.fields if f.type in ("hidden", "submit") and f.name not in fields}
        if other_names:
            try:
                pre_submit = await self._client.get(form.action_url, session=self._auth_session)
            except (ScopeViolationError, httpx.HTTPError):
                pre_submit = None
            if pre_submit is not None:
                fields = {**fields, **_live_field_values(pre_submit.text, other_names)}
        try:
            return await self._client.post(
                form.action_url,
                body=urlencode(fields),
                content_type="application/x-www-form-urlencoded",
                session=self._auth_session,
            )
        except (ScopeViolationError, httpx.HTTPError):
            return None

    async def _find_round_trip(self, marker: str, candidates: list[str]) -> httpx.Response | None:
        for url in candidates:
            try:
                response = await self._client.get(url, session=self._auth_session)
            except (ScopeViolationError, httpx.HTTPError):
                continue
            if _round_trips_unescaped(response.text, marker):
                return response
        return None

    async def _probe_export_endpoints(self, marker: str, base_url: str) -> httpx.Response | None:
        parsed = urlsplit(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        for path in _EXPORT_PATH_SHAPES:
            try:
                response = await self._client.get(origin + path, session=self._auth_session)
            except (ScopeViolationError, httpx.HTTPError):
                continue
            if response.status_code < 400 and _round_trips_unescaped(response.text, marker):
                return response
        return None

    async def _check_form(self, form: FormInfo, target_field: str, candidates: list[str]) -> Finding | None:
        marker = _marker()
        submit_response = await self._submit(form, target_field, _payload_for(marker))
        if submit_response is None:
            return None

        found_response = await self._find_round_trip(marker, candidates)
        if found_response is None:
            return None
        found_url = str(found_response.request.url)

        # §2 step 1: deterministic re-execution with a fresh marker and a
        # fresh submission — not just re-checking the same response.
        marker2 = _marker()
        submit_response2 = await self._submit(form, target_field, _payload_for(marker2))
        if submit_response2 is None:
            return None
        confirmed_response = await self._find_round_trip(marker2, [found_url])
        if confirmed_response is None:
            return None

        export_response = await self._probe_export_endpoints(marker2, found_url)
        return await self._build_finding(
            form, target_field, found_url, confirmed_response, export_response, _payload_for(marker2)
        )

    async def _build_finding(
        self,
        form: FormInfo,
        target_field: str,
        found_url: str,
        confirmed_response: httpx.Response,
        export_response: httpx.Response | None,
        payload: str,
    ) -> Finding:
        check_def = get_check("csv-formula-injection", filename=_CATALOG_FILE)
        if export_response is not None:
            context = f"a real CSV/export download at {export_response.request.url}"
            export_url = str(export_response.request.url)
            proof_steps = [
                f"4. Download the export at {export_url} and observe the payload is present, "
                "still starting with an unescaped '=' — a real attacker payload here would run "
                "as a formula the moment this file is opened in Excel or Google Sheets.",
            ]
        else:
            context = f"the stored/displayed page at {found_url} (no downloadable export endpoint was found)"
            proof_steps = [
                "4. No conventional export endpoint (checked: "
                f"{', '.join(_EXPORT_PATH_SHAPES)}) was found to confirm a real downloadable "
                "file — this finding confirms the unsanitized-storage precondition, not a "
                "verified end-to-end file download. If this application does export this data "
                "to CSV/XLSX elsewhere, that export is very likely also affected.",
            ]

        finding = Finding(
            scan_run_id=self._scan_run_id,
            agent_job_id=self._agent_job_id,
            check_id="csv-formula-injection",
            title=check_def.title,
            severity=check_def.severity,
            owasp_2025_category=check_def.owasp_2025_category,
            cwe_id=check_def.cwe_id,
            portswigger_reference_url=check_def.portswigger_reference_url,
            cvss_vector=check_def.cvss_vector,
            cvss_score=check_def.cvss_score,
            affected_endpoints=[form.action_url, found_url],
            plain_language_summary=check_def.plain_language_summary,
            technical_description=render_check_template(
                check_def.technical_description, form.action_url, {"context": context}
            ),
            steps_to_reproduce=[
                f"1. Submit {form.action_url} with the '{target_field}' field set to a value "
                'starting with "=" (e.g. "=SUM(1+1)").',
                f"2. Load {found_url}, where this value is stored/displayed back.",
                "3. Observe the value still begins with an unescaped '=' — confirmed here across "
                "two independent submissions with different marker values, and checked for the "
                "standard leading-quote/tab/CR mitigation, which was absent both times.",
                *proof_steps,
            ],
            remediation=check_def.remediation,
            references=[*check_def.references, check_def.portswigger_reference_url],
            confirmation_status="ai_confirmed",
        )
        request_raw = format_request_raw(confirmed_response)
        response_raw = format_response_raw(export_response or confirmed_response)
        async with self._client.session_lock:
            self._session.add(finding)
            await self._session.flush()
            self._session.add(
                Evidence(
                    finding_id=finding.id,
                    request_raw=request_raw,
                    response_raw=response_raw,
                    payload=payload,
                )
            )
            await self._session.commit()
        return finding
