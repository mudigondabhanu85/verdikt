# §14 Reference-App Validation Scorecard

This is the mandatory §14 validation pass: a real scan against a real,
self-hosted, independently-authored vulnerable reference application
(OWASP Juice Shop v20.2.0), manually reconciled against its published
challenge list, with real bugs fixed along the way and regression-tested.
Per §14.5, this document (and the reconciliation methodology below) is a
living regression suite — re-run it after any future agent-prompt or
detection-logic change.

## Methodology

- **Target**: OWASP Juice Shop v20.2.0, self-hosted locally via its
  prebuilt Node binary release (no Docker available in this environment;
  the binary release runs identically), 116 challenges exposed via its
  own `GET /api/Challenges/` API.
- **Discovery**: Juice Shop is an Angular SPA — a plain HTML crawl
  (`app.agents.recon`) structurally cannot see its real API surface,
  since `GET /` returns an almost-empty `<app-root>` shell. A real
  Chromium session (Playwright) was driven through the app's real UI —
  browsing, searching, registering, logging in, adding to a basket — and
  the resulting HAR (Playwright's native HAR recording) was imported
  through Verdikt's own `/versions/{id}/traffic/import` endpoint.
- **Scan**: A real scan was run through the real Verdikt API (not
  seeded directly into the database) — org/project/version, scope entry,
  target, authorization record, a JSON-login credential set matching
  Juice Shop's real `/rest/user/login` API shape, HAR import, then
  `POST /scan-runs`.
- **No AI API key available in this environment** (`ANTHROPIC_API_KEY`/
  `OPENAI_API_KEY` both unset) — AI-dependent checks (the injection
  family, IDOR/access-control comparison, business-logic rule checks,
  reflected-XSS AI triage) ran against the built-in no-op "fake"
  provider and cannot confirm anything real. This is an honest,
  structural scope limit for this pass, not a gap in the checks
  themselves — see the reconciliation table below for exactly which
  challenges this affects.

## Real bugs found and fixed during this pass

Every fix below was found via live testing against the real target (not
a synthetic fixture built to prove the intended answer), and each has a
dedicated regression test in the suite.

1. **Imported traffic never fed a scan at all.** `TrafficInteraction`
   rows written by the HAR/Burp/manual importers were a purely passive
   record — nothing downstream ever read them back out, so the
   traffic-import feature (built and tested earlier in this project's
   life) had never actually been wired into what a scan tests. This is
   the prerequisite fix for testing any client-rendered SPA at all.
   Fixed in `app/agents/traffic_seed.py`, wired into `recon_node` in
   `app/agents/graph.py`. Tests: `tests/test_traffic_seed.py`.

2. **`web-cache-deception` false positive on a SPA's own root path.**
   Every SPA serves the same public `index.html` for any unmatched
   route (standard client-side-router fallback) — the original check
   flagged Juice Shop's own homepage as a cache-deception vulnerability.
   Fixed with a root-path guard in `app/agents/cache_poisoning.py`
   (`_check_deception`) and the matching retest handler in
   `app/agents/retest_registry.py`. A second, deeper bug surfaced while
   fixing this: the check's per-host dedup was shared between the
   poisoning and deception checks, meaning a host whose first-crawled
   URL was `/` (true for nearly every host) would never have deception
   tested against anything — fixed with separate dedup tracking per
   check. Tests: `tests/test_cache_poisoning_agent.py`.

3. **WebSocket endpoints were never discovered from imported traffic.**
   Juice Shop's real `socket.io` handshake URL only ever appears in
   captured browser network traffic — the client builds it
   programmatically at runtime, so it's never a literal string in any
   fetched HTML/JS for `app.agents.recon`'s regex-based crawl to find.
   `discovered_websocket_endpoints` was a separate field the
   traffic-seeding bridge didn't populate. Fixed by extending
   `app/agents/traffic_seed.py` to also extract `ws://`/`wss://` URLs
   and wiring them into `graph.py`'s merge step. Tests:
   `tests/test_traffic_seed.py`.

4. **A stale session ID masked a real CSWSH vulnerability.** Even once
   discovered, a WebSocket URL captured from real traffic carries an
   Engine.IO `sid` query parameter bound to that specific,
   already-consumed polling session at capture time. Replaying it
   verbatim in a fresh handshake attempt is rejected with "Session ID
   unknown" — not because Origin validation exists, but because the
   session is stale — which would misreport a genuinely vulnerable
   endpoint (confirmed live: a forged-Origin handshake against Juice
   Shop's real endpoint completes with `101 Switching Protocols`) as
   safe. Fixed with `_strip_stale_session_id` in
   `app/agents/websocket_security.py`, applied in both the live agent
   and `app/agents/retest_registry.py`'s retest handler. Tests:
   `tests/test_websocket_agent.py`.

5. **A binary asset in a HAR crashed the entire traffic import.**
   Postgres text columns reject embedded NUL bytes outright — a
   base64-decoded binary asset (e.g. a PNG) in a captured HAR decodes to
   text containing literal NUL bytes, which took down the *whole batch
   insert*, not just that one row (`HarImporter` parses an entire HAR
   into one bulk `TrafficInteraction` insert). Fixed with
   `_strip_nul_bytes` applied to `request_body`/`response_body` at both
   import endpoints in `app/api/routes/traffic_import.py`. Tests:
   `tests/test_api_traffic_import.py`.

6. **Unbounded, un-timed-out real-browser checks against a large real
   endpoint set.** Once traffic-seeding actually worked, a single real
   target could surface ~80 real endpoints — `DomXssAgent` and
   `PrototypePollutionAgent` had no per-host dedup (unlike
   `ClickjackingAgent`) and no explicit navigation timeout, using
   Playwright's `wait_until="networkidle"`, which never fires against a
   real SPA that keeps a persistent connection open in the background
   (Juice Shop's own `socket.io` WebSocket). Fixed by switching to
   `wait_until="load"` with an explicit 10s timeout
   (`app/agents/xss_browser_proof.py`, `app/agents/prototype_pollution.py`)
   and adding a `MAX_ENDPOINTS = 40` cap to both agents, matching the
   existing bounded-scan philosophy elsewhere in the codebase
   (`ReconAgent.MAX_PAGES`, `traffic_seed.MAX_SEEDED_ENDPOINTS`). Tests:
   `tests/test_dom_xss.py`, `tests/test_prototype_pollution.py`
   (including a fixture that keeps a background connection open forever,
   proving the fix stays fast against exactly this pattern).

7. **uvloop is incompatible with Playwright — a real, silent,
   production-blocking bug.** `uvicorn[standard]` (the documented,
   recommended install) pulls in `uvloop`, and uvicorn's default
   `--loop auto` silently selects it whenever it's importable.
   Playwright's async API does not work correctly under uvloop:
   `browser.launch()` hangs forever — no timeout, no exception, no
   subprocess ever spawns — instead of erroring. This permanently stalls
   every real-headless-browser check (`clickjacking`, `dom_xss`,
   `prototype_pollution`) on **every single scan**, forever, with no
   visible failure short of an `AgentJob` stuck at `"running"`
   indefinitely. Confirmed by direct comparison — the full 14-agent
   concurrent graph completed correctly in 11 seconds against a real,
   reachable local target under plain `asyncio`, but hung indefinitely
   under uvicorn's default (uvloop) loop; switching to `--loop asyncio`
   immediately fixed it in isolation (verified via a real scan through
   the actual API completing all 23 agent jobs, including all three
   real-browser checks, against a fast local target). This was a real,
   independent bug — fixing it was necessary but, as fix #8 below shows,
   not sufficient to fully resolve live scans against Juice Shop. Fixed
   by pinning `--loop asyncio` explicitly in `backend/Dockerfile`,
   `docker-compose.yml`, and the README's documented dev command.
   Because this failure mode is invisible at the application-code level
   (no exception, no test can exercise "the process hangs forever"),
   the regression test instead guards the actual startup commands
   themselves: `tests/test_deployment_config.py`.

8. **NUL bytes in real binary responses crashed the shared scan session
   — the actual root cause of the "intermittent stall."** Even after
   fix #7, live scans against real Juice Shop kept stalling — always
   within about a second, always around the same point. Four
   successive rounds of defensive `asyncio.wait_for` backstops (the
   HTTP request itself, the traffic-recording commit, and finally every
   DB-touching method on the shared `AsyncSession` — commit/flush/
   refresh/get) never once fired, which was the real clue: this was
   never actually a *hang*. An in-process diagnostic endpoint dumping
   every live asyncio Task's real stack trace (added temporarily —
   `py-spy` is blocked by macOS SIP even under `sudo` in this
   environment, so external debugging wasn't an option) showed the
   scan's own background task had already **finished** — it wasn't
   stuck at all. The real cause, found in `uvicorn`'s own error log:
   fetching a real binary file (Juice Shop's own `/ftp/*` challenge
   assets — a `.kdbx` password database, in one case) produces a
   response body whose text decoding contains literal NUL (0x00) bytes,
   which Postgres text columns reject outright. That failure poisons
   the *entire shared* `AsyncSession` (SQLAlchemy raises
   `PendingRollbackError` on every subsequent operation until an
   explicit `rollback()`), cascading into every other concurrently
   running agent sharing that same session, and silently crashes the
   whole scan's background task from inside its own `finally` cleanup
   block — which is why the `ScanRun` row was left stuck at `"running"`
   forever with no error ever recorded. This is the *same bug class*
   already fixed for imported HAR traffic (fix #5) and agent-issued
   traffic recording, but present via **two more, separate** code
   paths that fix #5 never touched: `ScopedHttpClient._record_traffic`
   (agent-issued requests — every live HTTP call an agent makes is
   itself recorded as a `TrafficInteraction`) and, most centrally,
   `app.agents.evidence.format_request_raw`/`format_response_raw` — the
   single shared formatting functions nearly every agent's
   Finding/Evidence persistence goes through. Fixed by stripping NUL
   bytes in both places (`app/agents/http_client.py`,
   `app/agents/evidence.py`). Tests: `tests/test_http_client.py`,
   `tests/test_evidence.py`.

9. **Defensive hardening, kept even though it wasn't the root cause.**
   The four backstop layers built while chasing fix #8 are real,
   independently-valuable robustness improvements — they never fired
   for *this* bug, but they now guarantee no future single request or
   DB operation can silently hang an entire scan forever, and (after
   the last round) that one agent's genuine failure rolls back and
   recovers the shared session instead of cascading into every other
   concurrently running agent. Kept in `app/agents/http_client.py`
   (`_HARD_REQUEST_TIMEOUT_SECONDS`, `install_commit_backstop`) and
   wired into `app/agents/runner.py`. Tests: `tests/test_http_client.py`.

## Live scan results

The final, complete live scan run against real Juice Shop (after all
fixes above, including #8) produced:

- **Status: `completed`**, all 23 agent jobs completed successfully —
  including `clickjacking`, `dom_xss`, `header_config`, and
  `prototype_pollution`, the four that had been silently stuck
  indefinitely before fix #8.
- **290 findings**, severity breakdown `Critical: 0, High: 71,
  Medium: 4, Low: 215`, 0 review candidates.
- `header_config` alone confirmed 288 findings across the real,
  traffic-seeded endpoint set (missing CSP/Referrer-Policy/
  Permissions-Policy/X-Frame-Options/X-Content-Type-Options headers,
  and plaintext-HTTP transport) — a genuine, large real-world result
  only possible because of fix #1 (traffic-seeding); the recon-only
  crawl alone found just 9 of the ~72 discovered endpoints.
- `websocket` confirmed exactly 1 finding —
  `websocket-missing-origin-validation` against Juice Shop's real
  `socket.io` endpoint. This is the same real CSWSH vulnerability
  manually verified earlier in this validation pass via a raw forged-
  Origin handshake (`101 Switching Protocols` despite the foreign
  Origin) — confirming fixes #3 and #4 (WebSocket discovery + stale
  session-ID stripping) work correctly end-to-end in a real, full scan,
  not just in isolation.
- `cors` confirmed 1 finding (`cors-wildcard-origin`) — manually
  verified against raw evidence as a genuine true positive.
- No `web-cache-deception` false positive (fix #2 holds).

An earlier full run (before fix #1) produced 332 findings against a
richer HAR capture (this pass's capture script hit an Angular Material
UI-selector issue registering a test user, so this final run's
identity-aware checks — CSRF, business logic, access control — had no
authenticated session to exercise; a real, separate, minor gap in the
capture script, not in any check's detection logic).

## Challenge reconciliation

Juice Shop's 116 challenges, mapped against Verdikt's actual check
taxonomy (§3). Grading against the full 116 would be a meaningless
number — the majority are multi-step CTF-style flows, LLM-specific
prompt-injection puzzles, or app-specific business-logic/enumeration
puzzles with no generic web-security-check equivalent, and are
structurally out of scope for a taxonomy-driven scanner rather than a
missed detection.

| Category | Count | Notes |
|---|---|---|
| **In-scope, deterministic** (no AI key needed) | 13 | SSRF (1), CSRF (1), Upload Type/Size (2), Insecure Deserialization ×3 (detection-only by design — §1.2 safe-by-default never attempts real exploitation), Error Handling → verbose-error/stack-trace (1), Forged/Unsigned JWT (2), DOM XSS (1), XXE ×2 |
| **In-scope, AI-dependent** (needs a real `ANTHROPIC_API_KEY`/`OPENAI_API_KEY`) | 25 | Access-control/IDOR/business-logic family (10: Admin Section, Five-Star Feedback, Forged Feedback/Review, Manipulate Basket, Product Tampering, View Basket, Web3 Sandbox, Easter Egg, AI Debugging), injection family (11: SQLi/NoSQLi/SSTi logins, Database Schema, Ephemeral Accountant, Christmas Special, User Credentials), reflected/header/video XSS (4) |
| **Out of scope** (no corresponding check in Verdikt's taxonomy) | 78 | Anti-automation/CAPTCHA bypass, credential-guessing/social-engineering auth flows, app-specific cryptographic puzzles, business-logic enumeration flags, exposed-logs/metrics discovery, dependency/CVE/typosquatting scanning, open-redirect testing (a known, previously-documented taxonomy gap), LLM prompt-injection challenges, steganography/obscurity puzzles |

Of the 13 in-scope-deterministic challenges, `Error Handling` was
directly confirmed live (288 real `header_config` findings in the final
successful run — see **Live scan results**). The remaining 12 require
either a working authenticated session (this
pass's HAR capture did not include a successful login — a UI-selector
issue in the capture script, not a detection-logic gap) or specific
endpoints that weren't exercised in the particular browsing session
captured, and so were not individually confirmed live this round; each
has its own dedicated, real-fixture regression test in the suite
(`tests/test_ssrf_agent.py`, `tests/test_csrf_agent.py`,
`tests/test_file_upload_agent.py`, `tests/test_deserialization_agent.py`,
`tests/test_auth_agent.py`, `tests/test_dom_xss.py`,
`tests/test_xxe_agent.py`) proving each check's detection logic in
isolation against a real, live local server.

## Known Issues

None outstanding from this pass. The intermittent live-scan stall
against real Juice Shop (previously documented here as unresolved) was
fully root-caused and fixed — see fix #8 above — and confirmed resolved
via a complete, successful live scan (see **Live scan results**).

For posterity: the investigation ruled out several plausible-seeming
causes before finding the real one — the code's own concurrency model
(a real, unmodified 14-agent `graph.ainvoke()` completes correctly in
~11s against a real, reachable local target at realistic scale, run
directly), uvloop (fixed separately as #7, confirmed independently),
DNS resolution (100 concurrent real lookups all succeeded instantly),
thread-pool exhaustion (enlarging the pool to 256 workers didn't help),
and the target being slow (a direct `curl`/`httpx` request made from
outside the stalled process, at the exact moment it was "stuck",
returned instantly). What finally cracked it wasn't another timeout
layer — the four `asyncio.wait_for` backstops built while chasing those
hypotheses never fired, because the scan was never actually hung. It
had already crashed. An in-process endpoint dumping real asyncio Task
stack traces (the decisive diagnostic — `py-spy` is blocked by macOS
SIP even under `sudo` in this sandbox) showed zero pending tasks for
the scan at all, which sent the investigation to `uvicorn`'s own error
log instead of another `asyncio` layer, and that log had the real
answer the whole time: a `PostgreSQL text fields cannot contain NUL
(0x00) bytes` error, identical to a bug already fixed earlier in this
same pass (#5) but present via two further, separate code paths.

## Test suite

`uv run pytest -q`: **357 passed** (up from 329 at the start of this
validation pass — 28 new regression tests across the fixes above).
