"""CSV export (§8 reporting gap) — one row per Finding. Deliberately
flat/spreadsheet-friendly (affected endpoints joined with "; ", no
nested evidence) rather than a re-shaping of report.json — CSV's whole
point is pasting straight into a spreadsheet or ticketing bulk-import,
not being a lossless machine-readable export (report.json already is).
"""

import csv
import io

from app.models.finding import Finding

_COLUMNS = (
    "check_id",
    "title",
    "severity",
    "owasp_2025_category",
    "cwe_id",
    "cvss_score",
    "cvss_vector",
    "affected_endpoints",
    "confirmation_status",
    "retest_status",
    "plain_language_summary",
    "remediation",
)


def render_csv_report(findings: list[Finding]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(_COLUMNS)
    for finding in findings:
        writer.writerow(
            [
                finding.check_id,
                finding.title,
                finding.severity,
                finding.owasp_2025_category,
                finding.cwe_id,
                finding.cvss_score,
                finding.cvss_vector,
                "; ".join(finding.affected_endpoints),
                finding.confirmation_status,
                finding.retest_status,
                finding.plain_language_summary,
                finding.remediation,
            ]
        )
    return buffer.getvalue()
