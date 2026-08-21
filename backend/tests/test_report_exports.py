import io
import uuid

from docx import Document
from PIL import Image as PILImage
from pypdf import PdfReader

from app.models.finding import Evidence, Finding
from app.reporting.docx_report import render_docx_report
from app.reporting.html_report import render_html_report
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


def test_html_report_without_screenshots_omits_screenshot_section():
    finding = _finding_with_evidence()
    html = render_html_report(scan_run=_detail(), findings=[finding], executive_summary="summary")
    assert "Evidence — screenshot" not in html
