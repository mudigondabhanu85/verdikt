import uuid

import httpx
from sqlalchemy import select

from app.agents.deserialization import (
    DeserializationAgent,
    detect_from_cookies,
    detect_from_forms,
)
from app.agents.http_client import ScopedHttpClient
from app.agents.recon import FormField, FormInfo
from app.models.project import ScopeEntry
from app.models.review_candidate import ReviewCandidate
from app.models.scan import AgentJob, ScanRun
from tests.conftest import session_scope


def _response_with_cookie(url: str, cookie_header: str) -> httpx.Response:
    request = httpx.Request("GET", url)
    return httpx.Response(200, headers=[("set-cookie", cookie_header)], text="ok", request=request)


def test_detect_from_cookies_flags_java_signature():
    responses = {
        "http://site.test/": _response_with_cookie(
            "http://site.test/", "session=rO0ABXNyABFqYXZhLmxhbmcuSW50ZWdlcg==; Path=/"
        )
    }
    signals = detect_from_cookies(responses)
    assert len(signals) == 1
    assert signals[0].kind == "Java"
    assert signals[0].source == "cookie: session"


def test_detect_from_cookies_flags_php_signature():
    responses = {
        "http://site.test/": _response_with_cookie(
            "http://site.test/", 'data=O:8:"stdClass":0:{}; Path=/'
        )
    }
    signals = detect_from_cookies(responses)
    assert len(signals) == 1
    assert signals[0].kind == "PHP"


def test_detect_from_cookies_ignores_ordinary_cookies():
    responses = {
        "http://site.test/": _response_with_cookie("http://site.test/", "sid=abc123random; Path=/")
    }
    assert detect_from_cookies(responses) == []


def test_detect_from_forms_flags_dotnet_viewstate():
    forms = [
        FormInfo(
            action_url="http://site.test/submit",
            method="POST",
            fields=[FormField(name="__VIEWSTATE", type="hidden"), FormField(name="q", type="text")],
        )
    ]
    signals = detect_from_forms(forms)
    assert len(signals) == 1
    assert signals[0].kind == ".NET ViewState"


def test_detect_from_forms_ignores_forms_without_viewstate():
    forms = [FormInfo(action_url="http://site.test/submit", method="POST", fields=[FormField(name="q", type="text")])]
    assert detect_from_forms(forms) == []


async def test_agent_persists_review_candidates_never_findings(db_adapter):
    async with session_scope(db_adapter) as session:
        scan_run = ScanRun(version_id=uuid.uuid4(), status="running", requested_by=uuid.uuid4())
        session.add(scan_run)
        await session.commit()
        await session.refresh(scan_run)

        job = AgentJob(scan_run_id=scan_run.id, agent_type="deserialization", status="running")
        session.add(job)
        await session.commit()
        await session.refresh(job)

        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[ScopeEntry(host="site.test", port=80, in_scope=True)],
            db_session=session,
            transport=httpx.MockTransport(lambda r: httpx.Response(404)),
        )
        agent = DeserializationAgent(
            client, scan_run_id=scan_run.id, agent_job_id=job.id, db_session=session
        )

        responses = {
            "http://site.test/": _response_with_cookie("http://site.test/", "session=rO0ABXNy; Path=/")
        }
        forms = [
            FormInfo(
                action_url="http://site.test/submit",
                method="POST",
                fields=[FormField(name="__VIEWSTATE", type="hidden")],
            )
        ]

        candidates = await agent.run(responses, forms)
        assert len(candidates) == 2
        assert all(c.status == "pending" for c in candidates)
        assert {c.check_type for c in candidates} == {"potential-insecure-deserialization"}

        await client.aclose()

    async with session_scope(db_adapter) as session:
        stored_candidates = (await session.execute(select(ReviewCandidate))).scalars().all()
        assert len(stored_candidates) == 2
