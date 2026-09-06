import uuid

from sqlalchemy import select

from app.agents.chain_analysis import ChainAnalysisAgent
from app.ai.budget import BudgetGuard
from app.models.attack_chain import AttackChain
from app.models.finding import Finding
from app.models.scan import ScanRun
from tests.conftest import session_scope
from tests.fakes import ScriptedAIProviderAdapter


def _make_finding(scan_run_id, **overrides) -> Finding:
    defaults = dict(
        scan_run_id=scan_run_id,
        agent_job_id=uuid.uuid4(),
        check_id="stub",
        title="Stub finding",
        severity="Medium",
        owasp_2025_category="A05 Injection",
        cwe_id="CWE-79",
        portswigger_reference_url=None,
        cvss_vector="AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        cvss_score=5.0,
        affected_endpoints=["https://site.test/x"],
        plain_language_summary="stub summary",
        technical_description="stub description",
        steps_to_reproduce=["1. stub"],
        remediation="stub remediation",
        references=[],
        confirmation_status="ai_confirmed",
    )
    defaults.update(overrides)
    return Finding(**defaults)


async def _make_agent(session, provider, scan_run_id=None):
    scan_run = ScanRun(version_id=uuid.uuid4(), status="running", requested_by=uuid.uuid4())
    session.add(scan_run)
    await session.commit()
    await session.refresh(scan_run)

    guard = BudgetGuard(scan_run, session, provider)
    agent = ChainAnalysisAgent(
        scan_run_id=scan_run.id,
        agent_job_id=uuid.uuid4(),
        db_session=session,
        budget_guard=guard,
        ai_model="fake-model",
    )
    return agent, scan_run


def _xss_finding(scan_run_id) -> Finding:
    return _make_finding(
        scan_run_id,
        check_id="xss-reflected-self",
        title="Reflected XSS (self, requires victim's own session)",
        severity="Medium",
        owasp_2025_category="A05 Injection",
        cwe_id="CWE-79",
        cvss_vector="AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        cvss_score=5.4,
        affected_endpoints=["https://shop.test/account/profile?display_name=<script>PAYLOAD</script>"],
        plain_language_summary=(
            "An attacker can craft a link that, when the VICTIM clicks it while logged in, "
            "runs attacker-controlled JavaScript in the victim's own authenticated session "
            "on the account/profile page. It only fires in the victim's session, so on its "
            "own it 'just' lets an attacker run script as that one victim."
        ),
        technical_description=(
            "The display_name query parameter on GET /account/profile is reflected "
            "unescaped into the page. A crafted link containing a <script> payload executes "
            "in the browser of whoever clicks it while authenticated."
        ),
        steps_to_reproduce=[
            "1. Log in as the victim.",
            "2. Visit https://shop.test/account/profile?display_name=<script>...</script>.",
            "3. Observe the script executes in the victim's authenticated session.",
        ],
    )


def _csrf_finding(scan_run_id) -> Finding:
    return _make_finding(
        scan_run_id,
        check_id="csrf-email-change",
        title="CSRF on Email Change (no token validation)",
        severity="High",
        owasp_2025_category="A01 Broken Access Control",
        cwe_id="CWE-352",
        cvss_vector="AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
        cvss_score=7.5,
        affected_endpoints=["https://shop.test/account/change-email"],
        plain_language_summary=(
            "The account/change-email endpoint accepts a POST request that changes the "
            "logged-in user's email address without validating any CSRF token, and without "
            "requiring the user's current password. Any page the victim's browser loads "
            "while authenticated can silently submit this request on the victim's behalf."
        ),
        technical_description=(
            "POST https://shop.test/account/change-email accepts {new_email} with only the "
            "session cookie for authentication — no CSRF token, no re-authentication, no "
            "Origin/Referer check. A cross-site auto-submitting form can trigger it silently."
        ),
        steps_to_reproduce=[
            "1. While logged in as the victim, load a page containing an auto-submitting "
            "form that POSTs to https://shop.test/account/change-email with an "
            "attacker-controlled new_email value.",
            "2. Observe the victim's account email is changed to the attacker's address "
            "without any confirmation step.",
        ],
    )


def _unrelated_header_finding(scan_run_id) -> Finding:
    return _make_finding(
        scan_run_id,
        check_id="missing-csp",
        title="Missing Content-Security-Policy Header",
        severity="Low",
        owasp_2025_category="A02 Security Misconfiguration",
        cwe_id="CWE-693",
        cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        cvss_score=3.1,
        affected_endpoints=["https://shop.test/"],
        plain_language_summary="The site does not send a Content-Security-Policy header.",
        technical_description="No CSP header observed on any response from the homepage.",
        steps_to_reproduce=["1. Request https://shop.test/ and inspect response headers."],
    )


def _unrelated_sqli_finding(scan_run_id) -> Finding:
    return _make_finding(
        scan_run_id,
        check_id="sqli-error",
        title="SQL Injection (error-based) on Product Search",
        severity="Critical",
        owasp_2025_category="A05 Injection",
        cwe_id="CWE-89",
        cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_score=9.8,
        affected_endpoints=["https://shop.test/api/search?q=widget"],
        plain_language_summary=(
            "The /api/search endpoint's q parameter is concatenated directly into a SQL "
            "query on an entirely separate, unauthenticated public search page with no "
            "connection to the account/profile or account/change-email endpoints."
        ),
        technical_description=(
            "A single quote in the q parameter triggers a raw MySQL syntax error "
            "('...near \\'\\' at line 1') in the response body, confirming unsanitized "
            "string concatenation into the query."
        ),
        steps_to_reproduce=["1. Request https://shop.test/api/search?q=' and observe the DB error."],
    )


async def test_xss_and_csrf_compose_into_confirmed_account_takeover_chain(db_adapter):
    async with session_scope(db_adapter) as session:
        xss = _xss_finding(uuid.uuid4())
        csrf = _csrf_finding(uuid.uuid4())

        def respond_fn(messages):
            user_text = messages[-1].content
            if "Try to disprove" in user_text:
                return (
                    '{"vulnerable": true, "confidence": "high", '
                    '"reasoning": "The XSS genuinely runs in the victim session and the '
                    'change-email endpoint genuinely has no CSRF protection; chaining them '
                    'produces real account takeover, not just a plausible-sounding story."}'
                )
            return (
                '{"chains": [{"finding_ids": ["%s", "%s"], '
                '"title": "Self-XSS + CSRF Email Change -> Account Takeover", '
                '"severity": "Critical", '
                '"narrative": "The reflected XSS lets an attacker run JS as the victim; that '
                'script silently issues the CSRF-vulnerable change-email request, giving the '
                'attacker full control of the account.", '
                '"steps_to_reproduce": ["1. Attacker crafts a link combining the XSS payload '
                'with a change-email CSRF request.", "2. Victim clicks the link while logged '
                'in.", "3. The XSS payload silently submits the change-email form as the '
                'victim.", "4. Attacker resets the password using the new email and takes '
                'over the account."], '
                '"plain_language_summary": "Two individually moderate findings combine into '
                "full account takeover: a script-injection bug lets an attacker act as the "
                "victim, and a missing CSRF check lets that access silently change the "
                'account\'s email address."}]}'
            ) % (xss.id, csrf.id)

        provider = ScriptedAIProviderAdapter(respond_fn=respond_fn)
        agent, scan_run = await _make_agent(session, provider)

        xss.scan_run_id = scan_run.id
        csrf.scan_run_id = scan_run.id
        session.add(xss)
        session.add(csrf)
        await session.commit()
        await session.refresh(xss)
        await session.refresh(csrf)

        chains = await agent.run([xss, csrf])

        assert len(chains) == 1
        chain = chains[0]
        assert set(chain.finding_ids) == {str(xss.id), str(csrf.id)}
        assert chain.severity in ("Critical", "High")
        # escalated above the individual links' own severities (Medium, High)
        assert chain.severity != "Medium"
        assert len(chain.steps_to_reproduce) >= 2
        assert "disprove" not in chain.narrative.lower() or "could not" in chain.narrative.lower()

        persisted = (
            await session.execute(select(AttackChain).where(AttackChain.scan_run_id == scan_run.id))
        ).scalars().all()
        assert len(persisted) == 1


async def test_unrelated_findings_produce_no_chain(db_adapter):
    async with session_scope(db_adapter) as session:
        header = _unrelated_header_finding(uuid.uuid4())
        sqli = _unrelated_sqli_finding(uuid.uuid4())

        provider = ScriptedAIProviderAdapter.from_responses('{"chains": []}')
        agent, scan_run = await _make_agent(session, provider)

        header.scan_run_id = scan_run.id
        sqli.scan_run_id = scan_run.id
        session.add(header)
        session.add(sqli)
        await session.commit()
        await session.refresh(header)
        await session.refresh(sqli)

        chains = await agent.run([header, sqli])

        assert chains == []
        persisted = (
            await session.execute(select(AttackChain).where(AttackChain.scan_run_id == scan_run.id))
        ).scalars().all()
        assert persisted == []


async def test_adversarial_pass_rejects_a_manufactured_chain(db_adapter):
    """Triage proposes a chain (simulating an overeager first pass), but
    the independent adversarial validation pass disproves it — no
    AttackChain should be persisted, matching the same discipline
    business_logic.py's validation step already applies to single
    findings."""
    async with session_scope(db_adapter) as session:
        header = _unrelated_header_finding(uuid.uuid4())
        sqli = _unrelated_sqli_finding(uuid.uuid4())

        def respond_fn(messages):
            user_text = messages[-1].content
            if "Try to disprove" in user_text:
                return (
                    '{"vulnerable": false, "confidence": "high", '
                    '"reasoning": "These findings are on completely unrelated endpoints with '
                    'no real causal link; the proposed chain is a manufactured stretch."}'
                )
            return (
                '{"chains": [{"finding_ids": ["%s", "%s"], "title": "Manufactured chain", '
                '"severity": "Critical", "narrative": "unsupported stretch", '
                '"steps_to_reproduce": ["1. stub"], "plain_language_summary": "stub"}]}'
            ) % (header.id, sqli.id)

        provider = ScriptedAIProviderAdapter(respond_fn=respond_fn)
        agent, scan_run = await _make_agent(session, provider)

        header.scan_run_id = scan_run.id
        sqli.scan_run_id = scan_run.id
        session.add(header)
        session.add(sqli)
        await session.commit()
        await session.refresh(header)
        await session.refresh(sqli)

        chains = await agent.run([header, sqli])

        assert chains == []
        persisted = (
            await session.execute(select(AttackChain).where(AttackChain.scan_run_id == scan_run.id))
        ).scalars().all()
        assert persisted == []


async def test_fewer_than_two_findings_short_circuits_with_zero_ai_calls(db_adapter):
    async with session_scope(db_adapter) as session:
        only_finding = _unrelated_header_finding(uuid.uuid4())

        provider = ScriptedAIProviderAdapter.from_responses('{"chains": []}')
        agent, scan_run = await _make_agent(session, provider)

        only_finding.scan_run_id = scan_run.id
        session.add(only_finding)
        await session.commit()
        await session.refresh(only_finding)

        chains = await agent.run([only_finding])

        assert chains == []
        assert provider.calls == []

        chains_empty = await agent.run([])
        assert chains_empty == []
        assert provider.calls == []
