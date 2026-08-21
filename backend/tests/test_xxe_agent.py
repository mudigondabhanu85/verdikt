import uuid

import httpx

from app.agents.http_client import ScopedHttpClient
from app.agents.recon import FormField, FormInfo
from app.agents.xxe import XxeAgent
from app.models.project import ScopeEntry
from tests.conftest import session_scope


def _vulnerable_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/upload-order" and request.method == "POST":
        body = request.content.decode()
        if "<!ENTITY xxe SYSTEM" in body and "&xxe;" in body:
            return httpx.Response(
                200, text="Order: root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/nologin\n"
            )
        return httpx.Response(200, text="Order received: baseline")
    return httpx.Response(404)


def _safe_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/upload-order" and request.method == "POST":
        return httpx.Response(400, text="XML parsing disabled for this endpoint")
    return httpx.Response(404)


def _form() -> FormInfo:
    return FormInfo(
        action_url="http://site.test/upload-order",
        method="POST",
        fields=[FormField(name="order", type="text")],
    )


async def _run_agent(db_adapter, handler, forms):
    async with session_scope(db_adapter) as session:
        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[ScopeEntry(host="site.test", port=80, in_scope=True)],
            db_session=session,
            transport=httpx.MockTransport(handler),
        )
        agent = XxeAgent(
            client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
        )
        findings = await agent.run(forms)
        await client.aclose()
        return findings


async def test_xxe_file_disclosure_is_confirmed(db_adapter):
    findings = await _run_agent(db_adapter, _vulnerable_handler, [_form()])

    check_ids = {f.check_id for f in findings}
    assert "xxe-file-disclosure" in check_ids
    finding = next(f for f in findings if f.check_id == "xxe-file-disclosure")
    assert finding.severity == "High"
    assert finding.cwe_id == "CWE-611"


async def test_endpoint_that_rejects_xml_is_not_flagged(db_adapter):
    findings = await _run_agent(db_adapter, _safe_handler, [_form()])
    assert findings == []


async def test_get_forms_are_skipped(db_adapter):
    form = FormInfo(action_url="http://site.test/upload-order", method="GET", fields=[])
    findings = await _run_agent(db_adapter, _vulnerable_handler, [form])
    assert findings == []
