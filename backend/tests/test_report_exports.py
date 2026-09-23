import io
import uuid
from datetime import datetime, timezone

from docx import Document
from PIL import Image as PILImage
from pypdf import PdfReader

from app.models.autonomous_pentest import PentestCommand
from app.models.finding import Evidence, Finding
from app.reporting.docx_report import render_docx_report
from app.reporting.html_report import BrandingInfo, render_html_report
from app.reporting.pdf_report import render_pdf_report
from app.schemas.scan import ScanRunDetail


def _sample_png() -> bytes:
    buf = io.BytesIO()
    PILImage.new("RGB", (200, 100), color="red").save(buf, format="PNG")
    return buf.getvalue()


def _detail(**overrides) -> ScanRunDetail:
    defaults = dict(
        id=uuid.uuid4(),
        version_id=uuid.uuid4(),
        status="completed",
        started_at=None,
        completed_at=None,
        error=None,
        agent_jobs=[],
        finding_counts_by_severity={"Critical": 0, "High": 1, "Medium": 0, "Low": 0},
    )
    defaults.update(overrides)
    return ScanRunDetail(**defaults)


def _finding_with_evidence() -> Finding:
    finding = Finding(
        id=uuid.uuid4(),  # not auto-populated until flush; these tests never hit the DB
        scan_run_id=uuid.uuid4(),
        agent_job_id=uuid.uuid4(),
        check_id="xss-reflected",
        title="Reflected Cross-Site Scripting (XSS)",
        severity="High",
        owasp_2025_category="A05 Injection",
        cwe_id="CWE-79",
        cvss_vector="AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        cvss_score=6.1,
        affected_endpoints=["http://target.test/search?q=x"],
        plain_language_summary="An attacker-controlled link can run JavaScript in your browser.",
        technical_description="The q parameter is reflected unescaped into the HTML response.",
        steps_to_reproduce=["1. Visit the crafted link.", "2. The script executes."],
        remediation="Encode all user-controllable output for its rendering context.",
        references=["https://portswigger.net/web-security/cross-site-scripting"],
    )
    finding.evidence = Evidence(
        request_raw="GET /search?q=%3Cscript%3E HTTP/1.1\r\nHost: target.test\r\n",
        response_raw="HTTP/1.1 200 OK\r\n\r\n<p>Results for: <script></p>",
        screenshot_refs=["xss-browser-proof/abc/def.png"],
    )
    return finding


_NO_VISUAL_POC_TEXT = "No visual proof-of-concept for this finding"


def _pentest_command(**overrides) -> PentestCommand:
    defaults = dict(
        agent_job_id=uuid.uuid4(),
        sequence_number=1,
        tool_name="shell_exec",
        command="curl -X POST http://target.test/rest/user/login -d '{\"email\":\"a\"}'",
        stdout="HTTP/1.1 200 OK",
        stderr=None,
        exit_code=0,
        scope_decision="unknown",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        model_rationale="Testing the login endpoint for SQL injection.",
    )
    defaults.update(overrides)
    return PentestCommand(**defaults)


def _blind_finding() -> Finding:
    finding = _finding_with_evidence()
    finding.evidence.screenshot_refs = []
    return finding


def test_html_report_notes_missing_screenshot_for_a_blind_check():
    finding = _blind_finding()
    html = render_html_report(scan_run=_detail(), findings=[finding], executive_summary="summary")

    assert _NO_VISUAL_POC_TEXT in html
    assert "Evidence — screenshot" not in html


def test_html_report_omits_the_note_when_a_screenshot_is_present():
    finding = _finding_with_evidence()
    png_bytes = _sample_png()
    html = render_html_report(
        scan_run=_detail(),
        findings=[finding],
        executive_summary="summary",
        screenshots_by_finding_id={finding.id: [png_bytes]},
    )

    assert _NO_VISUAL_POC_TEXT not in html


def test_pdf_report_notes_missing_screenshot_for_a_blind_check():
    finding = _blind_finding()
    pdf_bytes = render_pdf_report(scan_run=_detail(), findings=[finding], executive_summary="summary")

    reader = PdfReader(io.BytesIO(pdf_bytes))
    text = "\n".join(page.extract_text() for page in reader.pages)
    assert _NO_VISUAL_POC_TEXT in text


def test_pdf_report_omits_the_note_when_a_screenshot_is_present():
    finding = _finding_with_evidence()
    png_bytes = _sample_png()
    pdf_bytes = render_pdf_report(
        scan_run=_detail(),
        findings=[finding],
        executive_summary="summary",
        screenshots_by_finding_id={finding.id: [png_bytes]},
    )

    reader = PdfReader(io.BytesIO(pdf_bytes))
    text = "\n".join(page.extract_text() for page in reader.pages)
    assert _NO_VISUAL_POC_TEXT not in text


def test_docx_report_notes_missing_screenshot_for_a_blind_check():
    finding = _blind_finding()
    docx_bytes = render_docx_report(scan_run=_detail(), findings=[finding], executive_summary="summary")

    document = Document(io.BytesIO(docx_bytes))
    all_text = "\n".join(p.text for p in document.paragraphs)
    assert _NO_VISUAL_POC_TEXT in all_text


def test_docx_report_omits_the_note_when_a_screenshot_is_present():
    finding = _finding_with_evidence()
    png_bytes = _sample_png()
    docx_bytes = render_docx_report(
        scan_run=_detail(),
        findings=[finding],
        executive_summary="summary",
        screenshots_by_finding_id={finding.id: [png_bytes]},
    )

    document = Document(io.BytesIO(docx_bytes))
    all_text = "\n".join(p.text for p in document.paragraphs)
    assert _NO_VISUAL_POC_TEXT not in all_text


def test_pdf_report_contains_expected_content():
    finding = _finding_with_evidence()
    pdf_bytes = render_pdf_report(
        scan_run=_detail(),
        findings=[finding],
        executive_summary="One high-severity reflected XSS issue was confirmed and needs prompt remediation.",
    )

    assert pdf_bytes[:5] == b"%PDF-"

    reader = PdfReader(io.BytesIO(pdf_bytes))
    text = "\n".join(page.extract_text() for page in reader.pages)

    assert "Verdikt Security Assessment Report" in text
    assert "reflected XSS issue was confirmed" in text
    assert "Reflected Cross-Site Scripting (XSS)" in text
    assert "CWE-79" in text
    assert "target.test/search" in text
    assert "Encode all user-controllable output" in text


def test_pdf_report_embeds_screenshot():
    finding = _finding_with_evidence()
    png_bytes = _sample_png()
    pdf_bytes = render_pdf_report(
        scan_run=_detail(),
        findings=[finding],
        executive_summary="summary",
        screenshots_by_finding_id={finding.id: [png_bytes]},
    )
    reader = PdfReader(io.BytesIO(pdf_bytes))
    text = "\n".join(page.extract_text() for page in reader.pages)
    assert "Evidence — screenshot" in text
    # The embedded image object must actually be present in the PDF.
    images_found = 0
    for page in reader.pages:
        images_found += len(page.images)
    assert images_found == 1


def test_pdf_report_skips_corrupt_screenshot_without_crashing():
    finding = _finding_with_evidence()
    pdf_bytes = render_pdf_report(
        scan_run=_detail(),
        findings=[finding],
        executive_summary="summary",
        screenshots_by_finding_id={finding.id: [b"not a real png"]},
    )
    assert pdf_bytes[:5] == b"%PDF-"
    reader = PdfReader(io.BytesIO(pdf_bytes))
    text = "\n".join(page.extract_text() for page in reader.pages)
    assert "Evidence — screenshot" not in text


def test_pdf_report_handles_zero_findings():
    pdf_bytes = render_pdf_report(
        scan_run=_detail(finding_counts_by_severity={"Critical": 0, "High": 0, "Medium": 0, "Low": 0}),
        findings=[],
        executive_summary="No confirmed findings.",
    )
    reader = PdfReader(io.BytesIO(pdf_bytes))
    text = "\n".join(page.extract_text() for page in reader.pages)
    assert "No confirmed findings for this scan run" in text


def test_docx_report_contains_expected_content():
    finding = _finding_with_evidence()
    docx_bytes = render_docx_report(
        scan_run=_detail(),
        findings=[finding],
        executive_summary="One high-severity reflected XSS issue was confirmed and needs prompt remediation.",
    )

    assert docx_bytes[:2] == b"PK"  # docx is a zip container

    document = Document(io.BytesIO(docx_bytes))
    full_text = "\n".join(p.text for p in document.paragraphs)
    for table in document.tables:
        for row in table.rows:
            full_text += "\n" + "\n".join(cell.text for cell in row.cells)

    assert "Verdikt Security Assessment Report" in full_text
    assert "reflected XSS issue was confirmed" in full_text
    assert "Reflected Cross-Site Scripting (XSS)" in full_text
    assert "CWE-79" in full_text
    assert "target.test/search" in full_text
    assert "Encode all user-controllable output" in full_text


def test_docx_report_embeds_screenshot():
    finding = _finding_with_evidence()
    png_bytes = _sample_png()
    docx_bytes = render_docx_report(
        scan_run=_detail(),
        findings=[finding],
        executive_summary="summary",
        screenshots_by_finding_id={finding.id: [png_bytes]},
    )
    document = Document(io.BytesIO(docx_bytes))
    full_text = "\n".join(p.text for p in document.paragraphs)
    assert "Evidence — screenshot" in full_text
    assert len(document.inline_shapes) == 1


def test_docx_report_skips_corrupt_screenshot_without_crashing():
    finding = _finding_with_evidence()
    docx_bytes = render_docx_report(
        scan_run=_detail(),
        findings=[finding],
        executive_summary="summary",
        screenshots_by_finding_id={finding.id: [b"not a real png"]},
    )
    document = Document(io.BytesIO(docx_bytes))
    full_text = "\n".join(p.text for p in document.paragraphs)
    assert "screenshot could not be embedded" in full_text
    assert len(document.inline_shapes) == 0


def test_docx_report_handles_zero_findings():
    docx_bytes = render_docx_report(
        scan_run=_detail(finding_counts_by_severity={"Critical": 0, "High": 0, "Medium": 0, "Low": 0}),
        findings=[],
        executive_summary="No confirmed findings.",
    )
    document = Document(io.BytesIO(docx_bytes))
    full_text = "\n".join(p.text for p in document.paragraphs)
    assert "No confirmed findings for this scan run" in full_text


def test_html_report_embeds_screenshot_as_base64_img():
    import base64

    finding = _finding_with_evidence()
    png_bytes = _sample_png()
    html = render_html_report(
        scan_run=_detail(),
        findings=[finding],
        executive_summary="summary",
        screenshots_by_finding_id={finding.id: [png_bytes]},
    )
    assert "Evidence — screenshot" in html
    expected_b64 = base64.b64encode(png_bytes).decode("ascii")
    assert f'src="data:image/png;base64,{expected_b64}"' in html


def test_html_report_highlights_the_evidence_payload():
    finding = _finding_with_evidence()
    finding.evidence.payload = "<script>"
    html = render_html_report(scan_run=_detail(), findings=[finding], executive_summary="summary")

    assert "<mark>&lt;script&gt;</mark>" in html
    # The payload text itself must never appear unescaped anywhere in
    # the document — it's attacker-controlled content (a real XSS
    # payload here) being rendered into a report someone opens in a
    # browser.
    assert "<script>" not in html


def test_html_report_with_no_payload_renders_raw_evidence_unhighlighted():
    finding = _finding_with_evidence()
    assert finding.evidence.payload is None
    html = render_html_report(scan_run=_detail(), findings=[finding], executive_summary="summary")

    assert "<mark>" not in html
    assert "&lt;script&gt;" in html  # still escaped, just not wrapped


def _command_injection_finding() -> Finding:
    """A command-injection-shaped finding: the full payload (with its
    "; echo " prefix) is what got *sent*, form-encoded in the request;
    only the bare marker is what actually comes back in the response
    (a shell echoes its output, not the command that produced it). A
    literal full-payload match finds nothing in either direction."""
    finding = _finding_with_evidence()
    finding.check_id = "command-injection"
    finding.evidence.request_raw = (
        "POST /vulnerabilities/exec/ HTTP/1.1\r\nHost: target.test\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
        "Submit=verdikt1&ip=%3B+echo+VERDIKT16912b40"
    )
    finding.evidence.response_raw = "HTTP/1.1 200 OK\r\n\r\n<pre>VERDIKT16912b40\n</pre>"
    finding.evidence.payload = "; echo VERDIKT16912b40"
    return finding


def test_html_report_highlights_form_encoded_payload_in_the_request():
    finding = _command_injection_finding()
    html = render_html_report(scan_run=_detail(), findings=[finding], executive_summary="summary")

    assert "<mark>%3B+echo+VERDIKT16912b40</mark>" in html


def test_html_report_highlights_embedded_marker_in_the_response():
    finding = _command_injection_finding()
    html = render_html_report(scan_run=_detail(), findings=[finding], executive_summary="summary")

    assert "<mark>VERDIKT16912b40</mark>" in html


def test_html_report_without_screenshots_omits_screenshot_section():
    finding = _finding_with_evidence()
    html = render_html_report(scan_run=_detail(), findings=[finding], executive_summary="summary")
    assert "Evidence — screenshot" not in html


def test_html_report_with_no_branding_is_unchanged():
    finding = _finding_with_evidence()
    html = render_html_report(scan_run=_detail(), findings=[finding], executive_summary="summary")
    assert '<img class="report-logo"' not in html
    assert html.count("Verdikt Security Assessment Report") >= 1
    assert "— Verdikt Security Assessment Report" not in html


def test_html_report_embeds_branding_logo_and_company_name():
    import base64

    finding = _finding_with_evidence()
    png_bytes = _sample_png()
    branding = BrandingInfo(company_name="Acme Corp", logo_bytes=png_bytes)
    html = render_html_report(
        scan_run=_detail(), findings=[finding], executive_summary="summary", branding=branding
    )
    assert "Acme Corp — Verdikt Security Assessment Report" in html
    expected_b64 = base64.b64encode(png_bytes).decode("ascii")
    assert f'src="data:image/png;base64,{expected_b64}"' in html


def test_docx_report_highlights_the_evidence_payload():
    finding = _finding_with_evidence()
    finding.evidence.payload = "<script>"
    docx_bytes = render_docx_report(scan_run=_detail(), findings=[finding], executive_summary="summary")

    document = Document(io.BytesIO(docx_bytes))
    from docx.enum.text import WD_COLOR_INDEX

    highlighted_runs = [
        run
        for paragraph in document.paragraphs
        for run in paragraph.runs
        if run.font.highlight_color == WD_COLOR_INDEX.YELLOW
    ]
    assert any(run.text == "<script>" for run in highlighted_runs), [r.text for r in highlighted_runs]


def test_docx_report_highlights_form_encoded_payload_and_embedded_marker():
    finding = _command_injection_finding()
    docx_bytes = render_docx_report(scan_run=_detail(), findings=[finding], executive_summary="summary")

    document = Document(io.BytesIO(docx_bytes))
    from docx.enum.text import WD_COLOR_INDEX

    highlighted_texts = [
        run.text
        for paragraph in document.paragraphs
        for run in paragraph.runs
        if run.font.highlight_color == WD_COLOR_INDEX.YELLOW
    ]
    assert "%3B+echo+VERDIKT16912b40" in highlighted_texts, highlighted_texts
    assert "VERDIKT16912b40" in highlighted_texts, highlighted_texts


def test_pdf_report_highlights_the_evidence_payload():
    finding = _finding_with_evidence()
    finding.evidence.payload = "<script>"
    pdf_bytes = render_pdf_report(scan_run=_detail(), findings=[finding], executive_summary="summary")

    reader = PdfReader(io.BytesIO(pdf_bytes))
    text = "\n".join(page.extract_text() for page in reader.pages)
    # The payload text still needs to actually render (ReportLab's
    # <span backColor> markup is stripped from extracted text, so this
    # confirms the escaped payload survived being wrapped, not that the
    # highlight color itself made it into the extracted text — pypdf
    # doesn't expose per-run background color).
    assert "<script>" in text


def test_pdf_report_matches_form_encoded_payload_and_embedded_marker():
    finding = _command_injection_finding()
    pdf_bytes = render_pdf_report(scan_run=_detail(), findings=[finding], executive_summary="summary")

    reader = PdfReader(io.BytesIO(pdf_bytes))
    text = "\n".join(page.extract_text() for page in reader.pages)
    assert "VERDIKT16912b40" in text


def test_docx_report_with_no_branding_has_no_extra_images():
    finding = _finding_with_evidence()
    docx_bytes = render_docx_report(
        scan_run=_detail(), findings=[finding], executive_summary="summary"
    )
    document = Document(io.BytesIO(docx_bytes))
    assert len(document.inline_shapes) == 0
    full_text = "\n".join(p.text for p in document.paragraphs)
    assert "Verdikt Security Assessment Report" in full_text
    assert "Acme Corp" not in full_text


def test_docx_report_embeds_branding_logo_and_company_name():
    finding = _finding_with_evidence()
    png_bytes = _sample_png()
    branding = BrandingInfo(company_name="Acme Corp", logo_bytes=png_bytes)
    docx_bytes = render_docx_report(
        scan_run=_detail(), findings=[finding], executive_summary="summary", branding=branding
    )
    document = Document(io.BytesIO(docx_bytes))
    assert len(document.inline_shapes) == 1
    full_text = "\n".join(p.text for p in document.paragraphs)
    assert any("Acme Corp — Verdikt Security Assessment Report" in h.text for h in document.paragraphs) or (
        "Acme Corp" in full_text
    )


def _same_check_findings(count: int) -> list[Finding]:
    """Several instances of the SAME check (same check_id/title, e.g. a
    missing security header confirmed on many crawled endpoints) — the
    real-world shape that produced a 629-page PDF from 291 near-duplicate
    header_config findings before grouping was added."""
    findings = []
    for i in range(count):
        finding = Finding(
            id=uuid.uuid4(),
            scan_run_id=uuid.uuid4(),
            agent_job_id=uuid.uuid4(),
            check_id="missing-csp",
            title="Missing Content-Security-Policy Header",
            severity="Low",
            owasp_2025_category="A02 Security Misconfiguration",
            cwe_id="CWE-693",
            cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
            cvss_score=3.1,
            affected_endpoints=[f"http://target.test/page{i}"],
            plain_language_summary="Shared summary text identical across every instance.",
            technical_description="Shared technical detail identical across every instance.",
            steps_to_reproduce=[f"1. Request http://target.test/page{i}.", "2. Observe no CSP header."],
            remediation="Shared remediation text identical across every instance.",
            references=["https://owasp.org/www-project-secure-headers/"],
        )
        finding.evidence = Evidence(
            request_raw=f"GET /page{i} HTTP/1.1\r\nHost: target.test\r\n",
            response_raw="HTTP/1.1 200 OK\r\n\r\n<html></html>",
            screenshot_refs=[],
        )
        findings.append(finding)
    return findings


def test_pdf_report_groups_findings_by_check_id():
    findings = _same_check_findings(5)
    pdf_bytes = render_pdf_report(
        scan_run=_detail(), findings=findings, executive_summary="summary"
    )
    reader = PdfReader(io.BytesIO(pdf_bytes))
    text = "\n".join(page.extract_text() for page in reader.pages)

    # ONE group heading, not five duplicate ones.
    assert text.count("Missing Content-Security-Policy Header") == 1
    assert text.count("Shared summary text identical across every instance.") == 1
    assert text.count("Shared remediation text identical across every instance.") == 1
    # But all five distinct endpoints still show up as instances.
    for i in range(5):
        assert f"target.test/page{i}" in text
    assert "5 instances" in text


def test_docx_report_groups_findings_by_check_id():
    findings = _same_check_findings(5)
    docx_bytes = render_docx_report(
        scan_run=_detail(), findings=findings, executive_summary="summary"
    )
    document = Document(io.BytesIO(docx_bytes))
    full_text = "\n".join(p.text for p in document.paragraphs)

    heading_texts = [p.text for p in document.paragraphs if p.style.name.startswith("Heading 2")]
    matching_headings = [h for h in heading_texts if "Missing Content-Security-Policy Header" in h]
    assert len(matching_headings) == 1, f"expected exactly one group heading, got {matching_headings}"
    assert full_text.count("Shared summary text identical across every instance.") == 1
    for i in range(5):
        assert f"target.test/page{i}" in full_text
    assert "5 instances" in full_text


def test_pdf_report_embeds_branding_logo_and_company_name():
    finding = _finding_with_evidence()
    png_bytes = _sample_png()
    branding = BrandingInfo(company_name="Acme Corp", logo_bytes=png_bytes)
    pdf_bytes = render_pdf_report(
        scan_run=_detail(), findings=[finding], executive_summary="summary", branding=branding
    )
    reader = PdfReader(io.BytesIO(pdf_bytes))
    text = "\n".join(page.extract_text() for page in reader.pages)
    assert "Acme Corp" in text
    images_found = sum(len(page.images) for page in reader.pages)
    assert images_found >= 1


def test_html_report_omits_the_transcript_section_for_a_deterministic_run():
    html = render_html_report(scan_run=_detail(), findings=[], executive_summary="summary")
    assert "Pentest Transcript" not in html


def test_html_report_includes_the_transcript_section_for_an_autonomous_run():
    cmd = _pentest_command(
        sequence_number=3,
        tool_name="shell_exec",
        command="sqlmap -u http://target.test/rest/user/login --batch --dbs",
        model_rationale="Testing for SQL injection with sqlmap.",
    )
    html = render_html_report(
        scan_run=_detail(mode="autonomous_ai"),
        findings=[],
        executive_summary="summary",
        pentest_commands=[cmd],
    )
    assert "Pentest Transcript" in html
    assert "#3" in html
    assert "sqlmap -u http://target.test/rest/user/login --batch --dbs" in html
    assert "Testing for SQL injection with sqlmap." in html
    assert "HTTP/1.1 200 OK" in html


def test_html_report_escapes_attacker_controlled_transcript_content():
    """The exact same reasoning as _highlight_payload's own docstring —
    a command's stdout can be attacker-influenced content (the target's
    own response body), and this report must never re-render that
    unescaped into an HTML document someone opens in a browser."""
    cmd = _pentest_command(stdout="<script>alert(1)</script>")
    html = render_html_report(
        scan_run=_detail(mode="autonomous_ai"), findings=[], executive_summary="summary", pentest_commands=[cmd]
    )
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_pdf_report_includes_the_transcript_section():
    cmd = _pentest_command(command="curl -s http://target.test/rest/user/login")
    pdf_bytes = render_pdf_report(
        scan_run=_detail(mode="autonomous_ai"),
        findings=[],
        executive_summary="summary",
        pentest_commands=[cmd],
    )
    reader = PdfReader(io.BytesIO(pdf_bytes))
    text = "\n".join(page.extract_text() for page in reader.pages)
    assert "Pentest Transcript" in text
    assert "curl -s http://target.test/rest/user/login" in text
    assert "Testing the login endpoint for SQL injection." in text


def test_pdf_report_omits_the_transcript_section_for_a_deterministic_run():
    pdf_bytes = render_pdf_report(scan_run=_detail(), findings=[], executive_summary="summary")
    reader = PdfReader(io.BytesIO(pdf_bytes))
    text = "\n".join(page.extract_text() for page in reader.pages)
    assert "Pentest Transcript" not in text


def test_docx_report_includes_the_transcript_section():
    cmd = _pentest_command(command="nmap -sV target.test")
    docx_bytes = render_docx_report(
        scan_run=_detail(mode="autonomous_ai"),
        findings=[],
        executive_summary="summary",
        pentest_commands=[cmd],
    )
    document = Document(io.BytesIO(docx_bytes))
    full_text = "\n".join(p.text for p in document.paragraphs)
    assert "Pentest Transcript" in full_text
    assert "nmap -sV target.test" in full_text
    assert "Testing the login endpoint for SQL injection." in full_text


def test_docx_report_omits_the_transcript_section_for_a_deterministic_run():
    docx_bytes = render_docx_report(scan_run=_detail(), findings=[], executive_summary="summary")
    document = Document(io.BytesIO(docx_bytes))
    full_text = "\n".join(p.text for p in document.paragraphs)
    assert "Pentest Transcript" not in full_text
