"""Maps a Burp Scanner REST API issue (documented shape — see
rest_client.py's module docstring) to our canonical Finding/Evidence
pair. Burp already performed its own detection/confirmation, so imported
issues are persisted as confirmation_status="analyst_confirmed" — the
closest fit in our two-value CONFIRMATION_STATUSES (§2): not our AI
pipeline's own confirmation, but vouched for by a trusted external tool
rather than an unconfirmed candidate.
"""

import base64
import re
import uuid

from app.models.finding import Evidence, Finding

_SEVERITY_MAP = {
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "information": "Low",
    "false positive": "Low",
}

_HTML_TAG_RE = re.compile(r"<[^>]+>")
_CWE_RE = re.compile(r"CWE-\d+")


def _strip_html(value: str | None) -> str:
    if not value:
        return ""
    text = _HTML_TAG_RE.sub("", value)
    return text.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").strip()


def _cwe_from_classifications(value: str | None) -> str:
    match = _CWE_RE.search(value or "")
    return match.group(0) if match else "CWE-0"


def _decode_b64(value: str | None) -> str:
    if not value:
        return ""
    try:
        return base64.b64decode(value).decode("utf-8", errors="replace")
    except (ValueError, UnicodeDecodeError):
        return value


def map_issue_to_finding(
    issue: dict, *, scan_run_id: uuid.UUID, agent_job_id: uuid.UUID
) -> tuple[Finding, Evidence | None]:
    severity = _SEVERITY_MAP.get(str(issue.get("severity", "")).lower(), "Low")
    endpoint = f"{issue.get('host', '')}{issue.get('path', '')}"

    issue_detail = _strip_html(issue.get("issue_detail"))
    issue_background = _strip_html(issue.get("issue_background"))

    finding = Finding(
        scan_run_id=scan_run_id,
        agent_job_id=agent_job_id,
        check_id=f"burp:{issue.get('type_index', 'unknown')}",
        title=issue.get("name") or "Burp-reported issue",
        severity=severity,
        owasp_2025_category="Imported from Burp Scanner",
        cwe_id=_cwe_from_classifications(issue.get("vulnerability_classifications")),
        portswigger_reference_url=None,
        cvss_vector="",
        cvss_score=0.0,
        affected_endpoints=[endpoint] if endpoint else [],
        plain_language_summary=issue_background or issue_detail or "No description provided by Burp.",
        technical_description=issue_detail or issue_background or "No description provided by Burp.",
        steps_to_reproduce=[issue_detail] if issue_detail else [],
        remediation=_strip_html(issue.get("remediation_detail"))
        or _strip_html(issue.get("remediation_background"))
        or "See Burp Scanner's remediation guidance for this issue type.",
        references=[_strip_html(issue.get("references"))] if issue.get("references") else [],
        confirmation_status="analyst_confirmed",
    )

    evidence = None
    burp_evidence = issue.get("evidence") or []
    if burp_evidence:
        first = burp_evidence[0].get("request_response") or {}
        request_raw = _decode_b64(first.get("request"))
        response_raw = _decode_b64(first.get("response"))
        if request_raw or response_raw:
            evidence = Evidence(request_raw=request_raw, response_raw=response_raw)

    return finding, evidence
