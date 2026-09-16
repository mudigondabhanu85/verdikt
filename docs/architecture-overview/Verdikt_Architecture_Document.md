# Verdikt
## AI Multi-Agent Web Application & API Security Testing Platform

**Architecture & Product Overview — Full Technical Reference**

*Every fact in this document, including the reference appendices, was verified
directly against the codebase at the time of writing (not reconstructed from
memory or prior documentation). Section 18 documents where the current build
diverges from the original design specification — honestly, both where the
build fell short and where it went further.*

---

## 1. Executive Summary

Verdikt is an AI-assisted, multi-agent DAST (Dynamic Application Security
Testing) platform that performs manual-assessment-quality web and API
penetration testing at automated speed. A single scan run executes a
**31-node LangGraph DAG** covering the OWASP Top 10 (2025) and the full
PortSwigger Web Security Academy topic list, followed by a cross-cutting
attack-chain-composition step that runs outside the graph proper — each
detection agent combining deterministic, re-executable HTTP-level probing
with LLM-assisted triage and adversarial validation. The result is a report
an experienced penetration tester would recognize as their own work:
confirmed findings only, real evidence (request/response pairs, browser
screenshots), plain-language and technical write-ups side by side, and a
remediation path for every issue.

The system is explicitly designed so **no single AI vendor is
load-bearing**. Every LLM-dependent agent talks to a pluggable `AIProviderAdapter`
interface — Claude, OpenAI, Gemini, Grok, or any self-hosted/in-house model
that speaks the OpenAI chat-completions protocol. Swapping providers is a
configuration action in the UI, not a code change; an org still configures
exactly **one** model — there is no per-check model picker anywhere in the
UI. What the backend *does* do automatically, invisibly to that
configuration, is substitute a same-family sibling of that one configured
model for a small number of specific tasks whose volume or complexity
profile differs sharply from the rest of the scan (§6.2) — this is
zero-configuration model tiering, not per-agent routing an analyst sets up.

**Current state, verified against the running codebase:** 52 files under
`app/agents/` (31 of them graph nodes, the rest shared infrastructure and
support modules), 30 API route modules, ~34 persisted data models, 10
external integrations, 18 YAML check catalogs (39 statically defined check
IDs, plus a further dozen dynamically-generated ones), 36 Alembic
migrations, 20 RBAC resources, and a backend test suite of **119 files /
667 collected tests** — all figures confirmed by direct inspection and by
running the test collector, not estimated. Full reference tables for every
one of these are in the appendices (§13–§24).

---

## 2. The Problem

Manual web/API penetration testing is thorough but doesn't scale: a
competent tester takes days per application, and demand for testing far
outpaces the supply of qualified testers. Existing DAST scanners scale but
don't produce trustworthy results — they're notorious for high
false-positive rates, shallow coverage of business logic and access control
issues, and reports nobody can act on without re-verifying every line by
hand.

Verdikt's design goal (from the original build specification) is concrete
and measurable:

> Scan a mid-size web app (50–150 endpoints, one auth role, one business
> workflow) and produce a report with **zero false positives** and
> **manual-assessment-equivalent finding depth**, in **under a day of
> wall-clock time**, for **under $20 of LLM spend**.

Two architectural decisions follow directly from that goal, and are fully
built and enforced in the running system today:

1. **Multi-agent, not one big prompt.** Thirty-one narrow, purpose-built
   detection agents each own one vulnerability class, run as parallel nodes
   in a LangGraph DAG, and use the cheapest technique that reliably confirms
   that class (a deterministic HTTP diff for SQL injection; a real
   headless-browser execution proof for XSS; a live out-of-band callback for
   SSRF). This keeps LLM usage focused on judgment calls — triage and
   adversarial validation — not busywork.
2. **Confirmed-Only Findings.** Nothing becomes a `Finding` on a hunch. A
   candidate must survive deterministic re-execution *and* an adversarial
   LLM validation pass that actively tries to argue the finding is a false
   positive. Anything that survives detection but can't be auto-confirmed
   becomes a `ReviewCandidate` for a human to promote or dismiss — never
   silently discarded, never silently over-claimed.

A third idea from the original design — **tech-stack fingerprinting to
narrow the test plan before it runs, for cost savings** — was scoped more
modestly than originally envisioned. See §2.1.

### 2.1 Smart Scan — what's actually built vs. originally envisioned

`fingerprint.py` runs a real, deterministic tech-stack fingerprint inline
inside the `recon` node (header/cookie/HTML-marker/error-signature
matching, zero extra requests) and the result is persisted and surfaced in
reports and the API (`scan_run.tech_stack_fingerprint`). What the original
design additionally called for — using that fingerprint to skip scheduling
entire categories of irrelevant checks, described in the spec as "likely
the single biggest token-savings lever available" — **is not built as
general graph-level routing**. The 31-node LangGraph DAG has zero
conditional edges; every node always runs regardless of the detected stack.
The one narrow exception that *is* built: SSTI probing inside `injection.py`
skips itself when no template-rendering signal was observed during recon.
This is called out explicitly (not glossed over) because it is the single
largest gap between the original cost-optimization design and the current
implementation — see §18 for the complete list of such deltas.

---

## 3. High-Level Architecture

```mermaid
flowchart TB
    subgraph Client["Browser"]
        FE["React + TypeScript SPA<br/>(Vite, TanStack Query, Tailwind)"]
    end

    subgraph Backend["Verdikt Backend — FastAPI (Python)"]
        API["REST API — 30 route modules<br/>JWT bearer auth, RBAC-enforced"]
        ORCH["Multi-Agent Orchestrator<br/>(LangGraph, 31-node DAG)"]
        AIABS["AI Provider Abstraction<br/>Claude / OpenAI / Gemini / Grok / Custom"]
        RPT["Reporting Engine<br/>HTML / PDF (reportlab) / DOCX / CSV / JSON"]
        VAULT["Credential Vault<br/>(envelope encryption, pluggable KMS)"]
    end

    subgraph Data["Persistence"]
        PG[("PostgreSQL<br/>~34 models")]
        OBJ[("Object Storage<br/>(screenshots, uploads, letters)")]
    end

    subgraph External["External Systems"]
        TARGET["Target Application<br/>(the system under test)"]
        LLM["LLM Provider<br/>Claude / OpenAI / Gemini / Grok /<br/>Any in-house OpenAI-compatible gateway"]
        JIRA["Jira"]
        SLACK["Slack"]
        TEAMS["Microsoft Teams<br/>(+ conversational bot)"]
        OUTLOOK["Outlook"]
        VGS["VGS<br/>(DAST governance tool)"]
        BURP["Burp Suite Professional"]
        IDP["SSO: SAML / OIDC"]
        CMDB["CMDB<br/>(generic REST asset lookup)"]
        PSWIG["PortSwigger Web<br/>Security Academy"]
        OSV["OSV.dev<br/>(open vulnerability DB)"]
    end

    FE <-->|"HTTPS / JWT"| API
    API --> ORCH
    API --> RPT
    API --> VAULT
    ORCH --> AIABS
    AIABS <-->|"chat completions"| LLM
    ORCH <-->|"scoped, allow-listed<br/>HTTP requests"| TARGET
    API <--> PG
    API <--> OBJ
    API -->|"ticket create/sync"| JIRA
    API -->|"scan complete"| SLACK
    API -->|"scan complete"| TEAMS
    API -->|"scan complete"| OUTLOOK
    API -->|"push confirmed findings"| VGS
    API <-->|"trigger / import"| BURP
    API <-->|"authn"| IDP
    API -->|"asset lookup"| CMDB
    API -->|"scrape topic write-ups"| PSWIG
    ORCH -->|"known-vulnerable-version lookup"| OSV
```

**Backend:** Python, FastAPI, SQLAlchemy 2.0 (async), Alembic migrations
(36 files, one linear chain), PostgreSQL. Dialect-agnostic ORM layer, so
the test suite runs against ephemeral SQLite with zero external services
(with one deliberately-accepted limitation: SQLite doesn't enforce
`ON DELETE CASCADE`, so cascade behavior is verified live against the real
Postgres, not by the unit suite).

**Frontend:** Vite + React + TypeScript, TanStack Query for server state,
React Router, Tailwind CSS. A hand-written typed fetch client
(`src/api/client.ts`, 23 namespaced sub-objects, 62 exported types in
`src/api/types.ts`) mirrors the backend's Pydantic schemas.

**Agent orchestration:** LangGraph builds a 31-node directed graph per scan
run, with genuine parallel fan-out where checks don't depend on each other
(12 nodes off `recon`, 14 more off `authenticated_recon`), and explicit
sequencing where they do (every authenticated check waits on `login`
succeeding). `chain_analysis` is deliberately *not* a graph node — it runs
as a separate step in `runner.py` after `graph.ainvoke()` completes, since
it needs the full, final set of findings from every other agent as its
input.

**Storage:** PostgreSQL for all structured data; a pluggable
`ObjectStorageAdapter` (local disk by default, S3-compatible for
production) for evidence screenshots, VGS report attachments, and
uploaded traffic files.

---

## 4. Core Data Model

Every engagement is modeled as a hierarchy that mirrors how a real pentest
is scoped and re-run over time. This is a simplified view for readability —
the full field-level reference for all ~34 models is in **Appendix
§15**.

```mermaid
erDiagram
    ORGANIZATION ||--o{ PROJECT : owns
    ORGANIZATION ||--o{ USER : has
    PROJECT ||--o{ VERSION : "has engagements"
    VERSION ||--o{ SCOPE_ENTRY : "allow-lists"
    VERSION ||--o{ TARGET : "points at"
    VERSION ||--o{ CREDENTIAL_SET : "authenticates via"
    VERSION ||--o{ BUSINESS_RULE : "declares"
    VERSION ||--o{ TRAFFIC_INTERACTION : "seeds from"
    VERSION ||--o{ SCAN_RUN : "is scanned by"
    SCAN_RUN ||--o{ AGENT_JOB : "runs"
    AGENT_JOB ||--o{ FINDING : "confirms"
    AGENT_JOB ||--o{ REVIEW_CANDIDATE : "queues"
    FINDING ||--o| EVIDENCE : "is proven by"
    FINDING ||--o{ FINDING_TICKET : "tracked as"
    FINDING ||--o{ RETEST_JOB : "re-verified by"
    SCAN_RUN ||--o{ ATTACK_CHAIN : "composes into"
    ATTACK_CHAIN ||--o{ ATTACK_CHAIN_EVIDENCE : "cites"
    TARGET ||--o| SCOPE_ENTRY : "auto-derives"
```

Key design points, each verified against real migration/model code:

- **Scope is a real technical control, not a UI reminder.** `ScopedHttpClient`
  (`app/agents/http_client.py`) checks every single outbound request against
  the Version's `ScopeEntry` allow-list before sending it — an agent
  structurally cannot reach a host outside scope (`is_in_scope()` in
  `app/agents/scope.py`). Adding a `Target` automatically derives its
  matching `ScopeEntry`.
- **Cascading deletes are explicit and real database-level behavior**, not
  application-level cleanup: `Finding.scan_run_id`/`agent_job_id`,
  `Evidence.finding_id`, `AttackChain.scan_run_id`,
  `AttackChainEvidence.attack_chain_id`, `AgentJob.scan_run_id`,
  `FindingTicket.finding_id`, `RetestJob.finding_id`,
  `ReviewCandidate.scan_run_id`/`agent_job_id`, `LoginMacro.credential_set_id`,
  and `VgsReportVulnerability.report_draft_id` /
  `VgsEvidenceStep.report_vulnerability_id` all carry real `ON DELETE
  CASCADE`. `TrafficInteraction.credential_set_id` and
  `VgsReportVulnerability.source_finding_id` use `SET NULL` instead —
  deleting the credential set or the source finding doesn't delete imported
  traffic history or a report entry that was copied from it, it just
  detaches the reference.
- **Findings vs. Review Candidates.** A `Finding` is a confirmed
  vulnerability with the full evidentiary bar met. A `ReviewCandidate` is a
  signal that survived detection but couldn't be auto-confirmed. Both are
  first-class, queryable, and reportable.
- **Credential secrets are envelope-encrypted** via a pluggable
  `KMSAdapter` (local Fernet key for dev, AWS KMS for production) before
  ever touching the database — this pattern is reused verbatim across
  `CredentialSet`, `AIProviderConfig`, `CMDBConfig`, `NotificationConfig`,
  `TicketingConfig`, `OidcProviderConfig`, and `VGSConfig` — every one of
  them stores `encrypted_*` + `masked_reference` and never returns
  plaintext.

---

## 5. The Multi-Agent Scanning Engine

### 5.1 Scan lifecycle — the real, verified 31-node DAG

```mermaid
flowchart LR
    A["POST /versions/{id}/scan-runs"] --> B["recon<br/>(unauthenticated crawl +<br/>inline tech-stack fingerprint)"]
    B --> U1["header_config"]
    B --> U2["host_header"]
    B --> U3["cors"]
    B --> U4["clickjacking"]
    B --> U5["xxe"]
    B --> U6["graphql"]
    B --> U7["deserialization"]
    B --> U8["ssrf"]
    B --> U9["prototype_pollution"]
    B --> U10["request_smuggling"]
    B --> U11["oauth"]
    B --> U12["cache_poisoning"]
    B --> L["login<br/>(per credential set)"]
    L --> E["authenticated_recon<br/>(full-depth authenticated crawl)"]
    E --> P["recon_planner<br/>(up to 2 propose-then-crawl rounds:<br/>AI suggests unlinked-but-plausible paths,<br/>each verified live, then crawled from —<br/>see §5.1a)"]
    P --> A1["dom_xss"]
    P --> A2["injection<br/>(SQLi / cmd-inj / SSTI /<br/>path traversal / NoSQLi)"]
    P --> A3["xss"]
    P --> A4["auth<br/>(JWT / session)"]
    P --> A5["access_control"]
    P --> BP["ai_business_logic_plan<br/>(AI proposes hypotheses only —<br/>never a verdict, see §5.3)"]
    BP --> A6["business_logic"]
    P --> A7["csrf"]
    P --> A8["stored_xss"]
    P --> A9["file_upload"]
    P --> A10["websocket"]
    P --> A11["weak_password_policy"]
    P --> A12["csv_injection"]
    P --> A13["session_invalidation"]
    P --> A14["vulnerable_components"]
    U1 & U2 & U3 & U4 & U5 & U6 & U7 & U8 & U9 & U10 & U11 & U12 --> G
    A1 & A2 & A3 & A4 & A5 & A6 & A7 & A8 & A9 & A10 & A11 & A12 & A13 & A14 --> G["chain_analysis<br/>(runs after the graph completes, over that<br/>run's Confirmed findings — composes<br/>multi-finding attack chains)"]
    G --> H["Report generation<br/>(HTML / PDF / DOCX / CSV / JSON /<br/>per-scan-run VGS-format DOCX)"]
    H --> I["Best-effort notify:<br/>Slack / Teams / VGS webhook/push"]
```

There are genuinely **no conditional edges anywhere in this graph** —
`add_conditional_edges` is never called. Every node listed always runs.
Recon deliberately runs twice: once unauthenticated (all a purely anonymous
visitor would ever see — usually just a login form), and once fully
authenticated after `login` succeeds. This was a real, live-found gap
during development — a pre-login-only crawl against DVWA discovered
exactly one form (the login form itself), leaving every other agent with
nothing to test. `recon_planner` and `ai_business_logic_plan` are later
additions to the original 24-node graph, both following the same
propose-then-verify discipline as everything else in §5.3 — an AI
suggestion is worth nothing here until something deterministic confirms it.
The newest four nodes — `weak_password_policy`, `csv_injection`,
`session_invalidation`, `vulnerable_components` — were ported from a
sibling DAST project and mapped onto this same architecture (deterministic
detector → LLM triage → deterministic re-execution → adversarial
validation, no LLM-only confirmation for any of them); see §7 for what
each one actually checks. `chain_analysis` runs outside the graph proper
(not a `graph.add_node` call, called directly by `runner.py` after
`graph.ainvoke()` returns), so it's not counted in the 31.

### 5.1a AI-driven crawl coverage — `recon_planner`'s propose-then-crawl loop

`recon_planner` (`app.agents.recon_planner.run_planner_rounds`) used to be
a single LLM call: propose unlinked-but-plausible paths against the site
map, verify each one for real, add whatever resolved to
`discovered_endpoints` as a standalone URL. That left a real coverage gap
— a confirmed suggestion like `/admin` was added as a leaf, but nothing
`/admin` itself linked to (`/admin/users`, `/admin/settings`, an audit
log, ...) ever got discovered, even though `ReconAgent` (§5) was already
built to crawl from a seed list, not just resolve it.

`run_planner_rounds` closes that gap: whatever a round confirms is handed
to a fresh `ReconAgent` as a crawl seed via the same `extra_seed_urls`
mechanism `recon`/`authenticated_recon` already use for traffic-imported
URLs, so the crawler actually explores from a confirmed AI suggestion the
same way it explores from anything it found itself. Each round then hands
the next round's LLM call a bigger site map — a suggestion that only makes
sense once `/admin/users` is already on the map (`/admin/users/export`,
say) gets a real shot in round 2. Bounded by
`Settings.recon_planner_max_rounds` (default **2**) rather than looping
until nothing new turns up, since each round is a real LLM call against
the scan's budget (`BudgetGuard`); a round that confirms nothing stops the
loop immediately rather than spending the remaining rounds for free.

### 5.2 What's in `app/agents/` beyond the 31 graph nodes

The `agents/` directory holds **52 files total** (up from 48), reflecting
the four newest detection nodes (`weak_password_policy.py`,
`csv_injection.py`, `session_invalidation.py`, `vulnerable_components.py`)
plus `browser_session.py`, a new shared helper (see below). Most files map
one-to-one onto a graph node; a few (`recon.py`, `login.py`) do double duty
as both a node's own implementation and shared infrastructure another node
reuses (`authenticated_recon` reuses the same `ReconAgent` as `recon`, for
instance). The ~21 files below are the shared infrastructure worth knowing
about beyond the checks themselves:

| File | Role |
|---|---|
| `graph.py` | `build_graph()` — wires the 31-node LangGraph DAG itself; the only file that knows the full node/edge topology |
| `http_client.py` | `ScopedHttpClient` — the scope-enforcement mechanism every other agent's requests pass through |
| `scope.py` | `is_in_scope()` allow-list matcher |
| `matrix.py` | Credential/privilege matrix engine (`Identity`, `MatrixEntry`) used by access-control and business-logic |
| `idor.py` | Shared numeric-ID substitution helpers |
| `probing.py` | Shared parameter-probing plumbing used by injection and XSS |
| `evidence.py` / `evidence_screenshot.py` | Raw HTTP evidence formatting; universal screenshot capture for non-browser-observable findings |
| `raw_http.py` | Raw-socket HTTP/1.1 primitives for wire-format-level checks (smuggling, WebSocket handshakes) |
| `clickjacking_proof.py` / `xss_browser_proof.py` | Real headless-browser proof mechanisms |
| `browser_session.py` | `seed_authenticated_context()` — the one shared helper for seeding a Playwright browser context with an `AuthenticatedSession`'s cookies/headers, replacing three independently-evolved copies of the same logic (§5.5) |
| `checks.py` | Deterministic, unit-testable Phase-1 header/config detection logic |
| `fingerprint.py` | Inline tech-stack fingerprinting (§2.1) |
| `login.py` / `macro.py` | Login form automation and Playwright-backed macro recording |
| `ssrf_callback.py` | The real local out-of-band callback listener SSRF confirmation depends on |
| `recon.py` | Crawler + form/parameter extraction |
| `retest.py` / `retest_registry.py` | Rescan/diff workflow and per-finding retest (reusing each check's own original detection logic) |
| `runner.py` | `execute_scan_run()` — the top-level entry point |
| `task_registry.py` | Tracks in-flight `asyncio.Task`s so cancellation actually reaches a running scan |
| `traffic_seed.py` | Seeds endpoint discovery from imported HAR/Burp/Zest/manual traffic for SPAs a plain crawl can't see |

### 5.3 Confirmed-Only Findings pipeline

```mermaid
flowchart LR
    A["Deterministic probe<br/>(HTTP-level signal)"] -->|"no signal"| X1["discarded"]
    A -->|"signal found"| B["LLM triage<br/>(classify: vulnerable?)"]
    B -->|"not vulnerable"| X2["discarded"]
    B -->|"vulnerable"| C["Deterministic<br/>re-execution"]
    C -->|"doesn't reproduce"| X3["discarded"]
    C -->|"reproduces"| D{"Can prove real-world<br/>impact automatically?<br/>(browser execution,<br/>OOB callback, etc.)"}
    D -->|"yes"| E["Finding<br/>(confirmed, with evidence)"]
    D -->|"no — needs human judgment"| F["ReviewCandidate<br/>(pending promotion)"]
```

Every step is genuinely re-executable: a Finding's "steps to reproduce" are
the exact request that was actually sent, not a templated example. Where
automatable, the strongest possible proof is used — a real headless
Chromium browser (Playwright) actually executing an injected script for
XSS, a real out-of-band callback for SSRF, a real second file upload and
fetch-back for file-upload vulnerabilities. Two categories are deliberately
**passive/detection-only, never actively exploited**, and this is a
documented design choice, not an oversight:

- `deserialization.py` only scans for recognizable serialized-object
  signatures (Java, PHP, .NET ViewState) — gadget chains are target-specific
  and attempting one live can crash the target.
- `request_smuggling.py` uses PortSwigger's documented *timing-based-only*
  methodology — it deliberately never actually smuggles a second request
  onto the wire, since doing so on a shared target risks corrupting or
  intercepting a real user's traffic.

### 5.4 A concrete, hard-won example: reflected XSS payload diversity

Early in development, the browser-execution proof for reflected XSS only
ever tried a plain `<script>alert(1)</script>` payload — which is precisely
what even the *weakest* real-world filters strip. A genuinely exploitable
reflection was being correctly detected but never auto-confirmed, because
the confirmation step's own payload was the one thing guaranteed to get
filtered. The fix — trying a `<script>` tag first, then an
`<img src=x onerror=...>` fallback with no "script" substring at all — was
verified live against a real DVWA instance across all four of its security
levels before being considered done.

### 5.5 More hard-won fixes: false positives, flakiness, and a shared-session hazard

Four more real bugs, found and fixed in the same DAST-porting pass that
added the four newest checks (§5.1):

- **Clickjacking false positive.** The check used to report "framable"
  the moment `X-Frame-Options`/CSP didn't explicitly block framing,
  without ever checking whether the target's real content actually
  rendered inside the iframe. `clickjacking_proof.py` now requires a real
  headless-browser render to confirm before flagging.
- **Session-selection flakiness.** Nine separate call sites used to grab
  `next(iter(sessions.values()))` — an arbitrary session, with no
  preference for one carrying real auth material over an empty/broken one
  left behind by a flaky macro replay. All nine now go through
  `pick_best_session()` (`app.agents.login`), which prefers a session that
  actually authenticated.
- **SPA shell-detection gap.** `fingerprint.py`'s Angular marker relied on
  `ng-version`, an attribute Angular's own runtime injects only *after*
  client-side bootstrap — essentially never present in a real app's raw,
  non-JS-executed HTML, which is all a plain HTTP fetch ever sees. Added
  `<app-root>`/`polyfills.js`/`runtime.js` markers, which are actually
  present in the raw shell.
- **Third-party IdP scope leak.** A login endpoint's auto-derived scope
  entry (very often an Okta/Auth0 host) used to be indistinguishable from
  a real, analyst-declared `Target`. `ScopeEntry.purpose` (`"target"` vs.
  `"login_only"`, migration `0034_scope_entry_purpose`) now tags which is
  which, and every discovered-endpoint/form/parameter list `graph.py`
  produces filters `login_only` entries out before handing them to any
  fuzzing agent — a third-party identity provider can no longer end up on
  the receiving end of injection/XSS/SSTI payloads just because the crawl
  happened to touch it during login.

And one consolidation: three independently-evolved copies of "seed a
Playwright browser context with an `AuthenticatedSession`" existed across
the codebase (two in `xss_browser_proof.py`, one in `stored_xss.py`), all
sharing a real bug — cookies were registered via Playwright's
`add_cookies([{..., url: ...}])`, which derives the cookie's effective
domain *and path* from whatever URL that call site happened to have handy,
rather than the host-wide scope a real session cookie with no `Path`
attribute actually has. A browser-based check navigating to a different
path than the one the cookie happened to be seeded against could silently
stop sending it — indistinguishable from "not logged in," no error
anywhere. `browser_session.py`'s `seed_authenticated_context()` is now the
single shared implementation (explicit `domain` + `path="/"`, plus
`localStorage` seeding via an init script, which none of the three copies
did), covered by a regression test that verifies against real Playwright
behavior.

---

## 6. AI Provider Abstraction — Any LLM, Configured Once

Every LLM-dependent agent goes through one interface
(`app.ai.adapters.base.AIProviderAdapter`), and which real model answers is
a runtime configuration choice, resolved in this **exact, code-verified
order** for every scan (`resolve_provider_and_model()` in
`app/ai/provider.py`):

```mermaid
flowchart TD
    A["Scan run starts"] --> B{"scan_run.ai_provider_config_id<br/>set and not deleted?"}
    B -->|"yes"| C["Use that AIProviderConfig"]
    B -->|"no"| D{"Org has an AIProviderConfig<br/>with is_default = True?<br/>(looked up via Project.org_id,<br/>joined through Version)"}
    D -->|"yes"| E["Use the org default"]
    D -->|"no"| F["Fall back to get_ai_provider()<br/>— the deployment's AI_PROVIDER<br/>.env setting + settings.ai_model"]
    C --> G["AIProviderAdapter.complete()"]
    E --> G
    F --> G
    G --> H["ClaudeAdapter / OpenAIAdapter / GeminiAdapter /<br/>GrokAdapter / GenericOpenAIAdapter<br/>(any OpenAI-chat-completions-compatible endpoint)"]
```

**Six adapter classes exist** (`app/ai/adapters/`): `ClaudeAdapter`,
`OpenAIAdapter`, `GeminiAdapter`, `GrokAdapter` (a subclass of
`GenericOpenAIAdapter`), `GenericOpenAIAdapter` itself (any OpenAI
chat-completions-compatible endpoint — self-hosted or an internal
enterprise gateway), and `NullAIProviderAdapter` (a genuine no-op, used
when `AI_PROVIDER=fake`, the framework's own default). Only Claude, OpenAI,
and `custom` are reachable as the deployment-wide `.env` default —
**Gemini and Grok are only reachable through a per-org `AIProviderConfig`
in the UI**, never via `.env`.

**Configuration is entirely UI-driven** for the per-org path: from the
Account page, an org registers an `AIProviderConfig` and marks it
"Default" (`is_default`, at most one per org, enforced by a database
constraint). From that point on, every scan that doesn't explicitly pick a
different provider routes through it automatically — no `.env` editing, no
redeploy, no code change. This directly answers a real deployment
constraint: an organization that can't or won't send data to a third-party
LLM vendor can point Verdikt at its own internal model and get identical
scanning behavior.

### 6.1 Cost governance — the real, enforced number

`app/ai/budget.py`'s `BudgetGuard` enforces `settings.max_llm_cost_usd_per_scan`
per `ScanRun`, atomically via a shared `asyncio.Lock`, and raises
`BudgetExceededError` once `scan_run.llm_cost_usd` reaches the cap — callers
catch this and mark the affected `AgentJob` as skipped, never silently
truncated. **The configured default cap is $2.00 per scan**, not the
original spec's $20 target figure — the spec's number was a top-line
product goal for total scan cost, while `MAX_LLM_COST_USD_PER_SCAN` is
the hard technical safety rail underneath it, and it is deliberately
tighter than the goal to leave headroom.

### 6.2 Automatic per-task model tiering

`app/ai/model_tiers.py`'s `resolve_tiered_model(configured_model, tier)` is
a pure, zero-configuration function `graph.py` and two other call sites use
to substitute a same-family sibling of the org's one configured model for
a small number of specific tasks — never a config surface an analyst has
to set up, never a new database column, never a new UI control:

| Tier | Used by | Why |
|---|---|---|
| `fast` | `deserialization`, `request_smuggling` | High-volume, simple triage calls — a cheaper model matters most here |
| `default` (unchanged) | Every other LLM-dependent node | The org's exact configured model, untouched |
| `reasoning` | `ai_business_logic_plan`, `business_logic`, `chain_analysis`, the executive summary | Low-volume but complex (multi-step business-logic hypotheses, attack-chain composition) or writing-quality-sensitive (the customer-facing executive summary) — a stronger model is affordable at this call volume |

Three model families are recognized (`app/ai/model_tiers.py`'s
`_MODEL_FAMILIES`), each verified against that provider's own current API
docs at the time this was written (September 2026): Claude
(`claude-haiku-4-5-20251001` / `claude-sonnet-5` / `claude-opus-5`), OpenAI
(`gpt-5-mini` / `gpt-5` / `gpt-5-pro`), and xAI Grok (`grok-4-fast` /
`grok-4` / `grok-4`, no separate reasoning tier above default as of this
writing). **Gemini is deliberately excluded** — Google is retiring the
entire Gemini 2.5 line in October 2026 and the exact current stable 3.x
model id wasn't reliably confirmable at writing time, so rather than ship
a guessed identifier that could silently 404 an org's scans later, a
Gemini-configured org (or any org on a model this table doesn't recognize
at all — a custom/self-hosted gateway included) gets exactly today's
single-model behavior for every tier, automatically and silently, never an
error.

This is the **second** attempt at task-aware model selection in this
codebase's history, and the first one that stuck — see §18, item 17 for
why the first attempt (`app.ai.model_routing`, migrations
`0029_ai_provider_config_model_tiers` / `0032_drop_ai_provider_model_tiers`)
was built and then deliberately reverted, and what's structurally
different this time.

---

## 7. Vulnerability Coverage

Coverage maps to the OWASP Top 10 (2025) and the PortSwigger Web Security
Academy topic list. The full, exact list of every check ID, its severity,
and its CWE is in **Appendix §17** (39 YAML-defined checks across 18
catalog files, plus a further ~13 dynamically-generated check IDs emitted
directly by agent code for parameterized findings like `sqli-error` /
`access-control-{comparison_type}`). By category:

- **Injection** — SQL injection (error- and boolean-based), OS command
  injection, server-side template injection, NoSQL injection, path
  traversal, CSV/formula injection (a leading `=`/`+`/`-`/`@` value that
  survives into an export without the standard leading-quote/tab/CR
  mitigation — a real finding, not a guess: the agent best-effort probes
  for an actual export endpoint and is honest in the write-up when it
  can't find one)
- **Broken access control** — IDOR, vertical/horizontal privilege
  escalation
- **Session & auth failures** — JWT alg-none/alg-confusion/weak-secret,
  missing expiration, weak session token entropy, session not invalidated
  on logout (confirmed via a dedicated disposable login and two
  independent logout/reuse cycles, never the shared scan session — §5.5),
  weak password policy acceptance (a real change-password form is
  confirmed to accept a one-character password via an actual re-login,
  with the original password always restored afterward — even on
  failure, logged as `CRITICAL`)
- **Cross-site scripting** — reflected/DOM/stored, with real
  headless-browser execution proof
- **Security misconfiguration** — 15 separate header/cookie/TLS/disclosure
  checks in the Phase-1 catalog alone (HSTS, CSP, X-Frame-Options, cookie
  flags, server-version disclosure, directory listing, weak TLS, etc.)
- **SSRF** — real out-of-band callback-verified, via a genuine local
  listener the scanner controls
- **OAuth** — `redirect_uri` allow-list bypass detection
- **Software & data integrity** — passive insecure-deserialization
  signature detection, client-side prototype pollution (verified in a real
  browser), known-vulnerable client-side components (a real headless
  browser reads each of 9 well-known JS libraries' own self-reported
  version off `window`, checked against the OSV.dev vulnerability
  database — deterministic end to end, no fingerprint-guessing)
- **XXE, GraphQL introspection, cache poisoning/deception**
- **File upload** — dangerous-extension acceptance, plus an
  image-polyglot bypass technique for endpoints that do enforce a
  getimagesize()-style content check
- **CSRF, CORS misconfiguration, clickjacking** — clickjacking is
  confirmed by a real headless-browser framing attempt that verifies real
  content actually rendered inside the iframe, not just a
  missing-header inference (§5.5)
- **HTTP request smuggling** — timing-based detection only, by design
- **WebSocket security** — cross-site WebSocket hijacking via
  Origin-validation bypass
- **Business logic** — analyst-declared rules covering resource isolation
  (IDOR), workflow-order bypass, price/quantity tampering, and race
  conditions

---

## 8. Retest, Rescan & Attack Chain Analysis

- **Rescan** (`retest.py`) — a full re-run of every agent against the
  current state of the target, diffed against the prior run: new findings,
  `still_open`, and `fixed`. A human's prior `risk_accepted`/
  `false_positive_after_review` decision is never silently overridden.
- **Retest** (`retest_registry.py`, `POST /findings/{id}/retest`) — a
  targeted, single-finding re-verification that deliberately reuses each
  check's own original detection logic (including its "private" helper
  functions) so a retest can never drift from the exact logic that earned
  the finding its original confirmation.
- **Attack Chain Analysis** (`chain_analysis.py`) — runs after every graph
  node completes, looking for standalone findings that compose into a more
  severe, realistic attack path (e.g. reflected XSS plus a missing CSRF
  token chaining into account takeover). Chains go through the same
  adversarial-validation discipline as individual findings.

---

## 9. Reporting

One dataset, multiple audiences, generated by 8 modules under
`app/reporting/`:

- **HTML / PDF / DOCX / CSV / JSON** exports, all generated from the same
  underlying `Finding` records. **PDF generation uses `reportlab`**, a
  pure-Python library with no native dependency — the original design
  suggested WeasyPrint, but its Pango/Cairo native dependency wasn't
  satisfiable in the build environment, so reportlab was substituted as a
  documented, deliberate implementation choice (same content: executive
  summary, severity table, per-finding sections).
- **Finding grouping** (`grouping.py`) — `group_findings()` groups raw
  `Finding` rows by `(check_id, title)`, capping detailed evidence at 5
  instances per group with the rest summarized by endpoint only. Reused by
  both the standard report pipeline and the VGS report-builder's
  auto-seed/available-findings logic.
- **Executive summary** (`executive_summary.py`) — an LLM-generated
  plain-language narrative for non-technical stakeholders, generated once
  per scan run and cached on `scan_run.executive_summary` (never re-spends
  budget on repeated report requests).
- **Org branding** (`org_branding.py` model + routes) — logo and primary
  color on every generated report.
- **VGS-shaped DOCX** (`vgs_docx_report.py`) — matches the original
  standalone VGS tool's report format (pie chart, version-history table).
- **Evidence payload highlighting** (`Evidence.payload`, migration
  `0035_evidence_payload`) — the exact substring that proves a finding (a
  forged Origin value, an executed XSS marker, the weak password itself,
  the pre-logout cookie a post-logout request still succeeded with, ...),
  visually highlighted wherever `request_raw`/`response_raw` is shown:
  `<mark>` in HTML, a highlighted run in DOCX, a background-color span in
  PDF. Nullable and degrades gracefully — a finding without a captured
  payload just shows unhighlighted raw text, never an error. Wired into
  all four of the newest checks plus CSRF, proven first as a retrofit.
- **"No visual proof-of-concept" note** — every report format now says so
  explicitly whenever a finding's `screenshot_refs` end up empty, instead
  of silently omitting the whole screenshot section (which used to read
  as "this section was forgotten," not "this check type has no visual
  proof to show").

---

## 10. VGS Integration — Three Complementary Modes, All Built

1. **Decoupled webhook push** (`app/integrations/vgs/client.py`'s
   `VGSClient`, `VGSConfig` model, `push_findings_to_vgs` trigger) — on scan
   completion, Verdikt POSTs structured findings to VGS's own ingestion
   webhook, tagged `source: ai-multi-agent`. Best-effort by design — one
   broken/unreachable webhook config never fails the scan itself.
2. **Native report-builder port** — VGS's own manual report-building
   workflow ported natively into Verdikt as its own top-level workspace
   (`/vgs`, `/vgs/:versionId` routes; `vgs_vulnerabilities.py`'s
   `library_router` and `draft_router`; `VgsReportDraft` /
   `VgsReportVulnerability` / `VgsEvidenceStep` / `VgsVulnerabilityLibraryEntry`
   models):
   - The **Vulnerability Picker** offers real, scan-confirmed findings
     grouped by vulnerability type (via the same `group_findings()` used by
     standard reports), auto-seeded into a new report draft — and re-seeded
     on every load, not just the first. A dedicated `auto_seeded_finding_ids`
     column (JSON list on `VgsReportDraft`) tracks every `Finding.id` ever
     offered, kept forever even after the analyst deletes the resulting
     vulnerability — this is what lets a later scan's newly-confirmed
     vulnerability class appear automatically without resurrecting something
     already deliberately removed (the two behaviors are genuinely in
     tension; this is the fix that satisfies both).
   - Each selected vulnerability supports **delete and in-place severity
     editing** directly from the picker, not just from the curated library.
   - **Manage Vulnerabilities** includes a one-click **"Load from
     PortSwigger"** action (`app/integrations/portswigger/client.py`'s
     `fetch_topics()`, 13 real seeded Web Security Academy URLs) — a native
     port of the original standalone VGS tool's scrape-to-Excel workflow,
     collapsed into a single server-side action.
   - **Evidence** supports numbered steps, each with one or more
     screenshots addable at any time, not just at step creation.
   - **Generate Report** (`GET /versions/{id}/vgs-report-draft/report.docx`)
     produces the same DOCX shape as the original VGS tool.
3. **Per-scan-run VGS-format export, with no curation step at all**
   (`GET /scan-runs/{id}/report.vgs.docx`) — the newest of the three modes.
   Every finding from one specific scan run, grouped the same way the
   curated workspace groups them, rendered straight into the VGS DOCX shape
   (pie chart, summary table, per-vulnerability detail sections) as one
   transient, unpersisted document — nothing is written to
   `VgsReportDraft`/`VgsReportVulnerability` for this path. This is the
   "I just want the VGS format for this one scan, right now" case; the
   curated workspace above remains the tool for building a report that
   blends multiple scans, ad-hoc entries, and manual curation.

This is notably **more** than the original design called for — the spec
recommended starting with the webhook path alone; both the native
report-builder port and the per-scan-run export were built in addition.

---

## 11. Enterprise Hardening

- **RBAC** — a real DB-backed `role_permissions` table across **20
  resources × 4 actions** (80 grantable permission cells), not hardcoded
  role checks. Full matrix in **Appendix §21**.
- **SSO** — SAML and OIDC, per-org, each with configurable default role
  assignment for federated sign-ins. (Note: these live under `app/auth/`,
  not `app/integrations/` — they're treated as part of the authentication
  core, not an optional integration.)
- **Ticketing & notifications** — Jira ticket creation directly from a
  Finding; Slack, Microsoft Teams, and Outlook notifications on scan
  completion; a genuine conversational **Microsoft Teams bot**
  (`app/integrations/teams_bot/`) with real command classes (`ScanCommand`,
  `StatusCommand`, `NewProjectCommand`) for triggering/checking scans from
  chat — built beyond what the original design specified (which called for
  a generic notification adapter only, not an interactive bot).
- **CMDB integration** — a generic, configurable REST client (`CMDBClient`:
  URL template, auth header, dot-path JSON field mappings) rather than an
  abstract per-vendor interface, a deliberate choice since there's no
  single real CMDB API to build and test against honestly.
- **API keys** — long-lived, revocable tokens for CI/automation clients.
- **Audit log** — every state-changing action recorded with actor, action,
  resource, and metadata (secrets always excluded).
- **Cost governor** — see §6.1.

---

## 12. Security Model

- **Technical scope enforcement** — `ScopedHttpClient` checks every single
  outbound request against the Version's scope allow-list before it's sent.
- **Credential envelope encryption** — every stored secret is encrypted via
  a pluggable `KMSAdapter` before touching the database; API responses only
  ever include a masked reference.
- **Safe-by-default agent behavior** — the File Upload agent never actually
  executes an uploaded payload; the SSRF agent uses only a scanner-controlled
  callback target; the deserialization and request-smuggling agents are
  deliberately passive/detection-only (§5.3) to avoid target-corrupting or
  traffic-intercepting side effects.
- **What the original design called for but is not built**: a
  pre-scan **authorization gate** (requiring an uploaded authorization
  letter/attestation before any active testing could run) was built and
  then **fully removed** — the model, its table, and every reference to it
  were deleted (migration `0022_drop_authorization_records.py`). Scope
  enforcement remains and is real; the authorization-letter half of that
  original guardrail does not exist in the system today. Configurable
  **human-in-the-loop approval checkpoints** before injection payloads or
  state-changing business-logic tests were also specified but never built.
  See §18 for the full delta list.

---

## 13. Deployment

Two supported paths — both fully built, neither a stub. **Docker Compose**
brings up the full stack from a single command; a **manual (native)** setup
runs Python/Node directly on the host against any reachable Postgres. See
the top-level `README.md` for the exact commands for each; this section
covers what's architecturally true of each path.

### 13.1 Docker Compose

Verified end-to-end against a completely fresh environment (empty Postgres
volume, no host `.venv`/`node_modules`):

```mermaid
flowchart TB
    subgraph Host["Host Machine (macOS / Linux / Windows)"]
        subgraph Compose["docker compose up --build"]
            DB[("db<br/>postgres:16-alpine<br/>named volume: verdikt_pgdata<br/>host port 5433 (avoids native-Postgres collision)")]
            BE["backend<br/>python:3.12-slim + Playwright/Chromium<br/>+ Xvfb/x11vnc/fluxbox/novnc<br/>(installed at BUILD time)<br/>runs `alembic upgrade head`<br/>then uvicorn --loop asyncio"]
            FEC["frontend<br/>node:22-slim, real Vite dev server<br/>npm run dev -- --host 0.0.0.0"]
        end
        Browser["Browser<br/>localhost:5173"]
    end
    BE -->|"db:5432"| DB
    Browser -->|"HTTP"| FEC
    Browser -->|"HTTP :8095"| BE
    Browser -->|"VNC-in-iframe<br/>127.0.0.1:6080"| BE
```

- **`--loop asyncio` is not a stylistic choice** — uvicorn's default
  `--loop auto` silently selects `uvloop`, which is incompatible with
  Playwright's async browser launch and hangs forever with no error
  message. This was found by actually running the container against a
  live Juice Shop target, not by reading documentation.
- **`--build` is not optional either.** Plain `docker compose up` / `up -d`
  reuses whatever image was built last, even after `Dockerfile` itself has
  changed — a real, live-found incident: the backend image was rebuilt once
  with `xvfb`/`x11vnc`/`fluxbox`/`novnc` newly added to `Dockerfile`, but a
  later `docker compose up -d` reused the *previous* cached image, so the
  login-macro recorder's VNC stack silently never started while `/health`
  reported the container fine throughout. Fixed at the source, not just in
  the docs: `start-display.sh` now pre-flight-checks each binary exists and
  confirms (via `pgrep`, needing the added `procps` package) that each
  process actually stayed running after launch — either one unmistakable
  success line, or a banner naming exactly what's missing and that a
  `--build` is needed. It never fails the container outright over this —
  scanning, the API, and the standalone browser-extension recorder (below)
  don't depend on VNC at all.
- **A second, distinct live-found VNC failure mode**: an uncleanly stopped
  container (an OOM kill, `exit 137` — anything short of a graceful
  `SIGTERM` `Xvfb` gets to handle) leaves `/tmp/.X99-lock` behind. On the
  next `docker compose up`/`restart` (same container, same filesystem),
  `Xvfb` sees that stale lock, assumes display `:99` is already owned by a
  live server, and refuses to start — cascading into `x11vnc` failing to
  connect and the whole stack reporting dead, which is what silently broke
  the in-app "Record macro" button. `start-display.sh` now clears the
  stale lock/socket before launching `Xvfb` and passes `-nolock` as
  defense in depth.
- **`localhost`/`127.0.0.1` targets are not reachable from inside this
  container** on Docker Desktop (macOS/Windows) — it's isolated from the
  host's own loopback. A target/credential/traffic-import URL pointing at
  a host-run service (a local DVWA or Juice Shop container, say) needs
  `host.docker.internal` instead, exactly like the native-Postgres
  override below — a real, live-found incident: every such target across
  an existing engagement was silently unreachable, so every scan against
  them ran to completion and reported zero findings with no visible
  error, not a connection failure.
- Migrations run automatically on container start (a no-op once already
  current) — a fresh database gets its schema with zero manual steps.
- The backend's build-time virtualenv is protected from the dev bind-mount
  via a masking Docker volume (`backend_venv:/app/.venv`), so the container
  never silently inherits a host's binary-incompatible Python environment;
  the frontend uses the equivalent `node_modules` mask. A third mount
  (`./browser-extension:/browser-extension:ro`) exposes the standalone
  extension's source (§13.3) to the "Download extension" button, since it
  lives as a sibling of `backend/`, not inside it.
- The frontend Dockerfile runs the real Vite dev server (with HMR), not a
  production build — its own comment notes a production multi-stage/nginx
  build is a reasonable follow-up once there's an actual deployment target.
- `.gitattributes` (`* text=auto eol=lf`) normalizes line endings across
  macOS/Linux/Windows checkouts.
- A machine already running its own native Postgres can point the backend
  container at it instead of the bundled `db` service via a git-ignored
  `docker-compose.override.yml` (`DATABASE_URL` → `host.docker.internal`)
  — machine-local by design, never committed.

### 13.2 Manual (native) setup

No Docker at all: `uv sync` + `alembic upgrade head` + `uvicorn` for the
backend, `npm install` + `npm run dev` for the frontend, against any
Postgres the operator points `DATABASE_URL` at. Functionally equivalent to
the Docker path with one real exception: the in-app "Record in-browser"
login-macro recorder needs the Xvfb/x11vnc/noVNC display stack above, which
only exists inside the Docker image — there is no native macOS/Windows
equivalent shipped. §13.3 is the answer for this path.

### 13.3 Standalone browser extension (login-macro recording without Docker)

`browser-extension/` — a real, separate Chrome/Edge Manifest V3 extension
producing the exact same `LoginMacro.steps` JSON shape as the in-app
Playwright recorder (`POST /versions/{id}/credentials/{id}/macros/upload`
accepts either interchangeably; both are replayed by the identical
`MacroPlayer`). Since neither Chrome nor Edge allows a web page to install
an unpublished extension directly — inline installation was removed
platform-wide years ago, and this one isn't on the Web Store — "Download
extension (.zip)" (next to **Record macro** in the Credentials tab,
backed by `GET /browser-extension/download`, which zips the source on
demand so the download is always in sync with the checked-in extension) is
the practical equivalent: download, `chrome://extensions` → Developer
mode → Load unpacked, record, export, upload.

---

## 14. Testing & Quality Discipline

- **119 test files, 667 collected tests** — confirmed by running
  `pytest --collect-only`, not estimated.
- Real fixtures over mocks wherever practically possible: real local HTTP
  servers standing in for a target application, a real headless browser
  for execution proofs, real cryptographic round-trips for the credential
  vault.
- **Live-validated**, not just unit-tested: run against a real, running
  OWASP Juice Shop instance and a real DVWA instance across all four of its
  security levels (Low, Medium, High, Impossible), with results manually
  cross-checked against what's actually exploitable at each level.
- Every bug fix in this system's history was root-caused against a real
  target, not inferred from a stack trace alone.

---

## 15. Appendix — Full Data Model Reference

| Model | Table | Key columns / FKs (ondelete) |
|---|---|---|
| `AIProviderConfig` | `ai_provider_configs` | `org_id`, `provider`, `model`, `base_url`, `auth_type`, `encrypted_api_key`, `masked_reference`, `is_default` |
| `ApiKey` | `api_keys` | `org_id`, `user_id`, `label`, `key_prefix`, `hashed_key` (unique), `last_used_at`, `revoked_at` |
| `AttackChain` | `attack_chains` | `scan_run_id`→scan_runs **CASCADE**, `title`, `severity`, `finding_ids` (JSON), `plain_language_summary`, `narrative`, `confirmation_status` |
| `AttackChainEvidence` | `attack_chain_evidence` | `attack_chain_id`→attack_chains **CASCADE** |
| `AuditLogEntry` | `audit_log_entries` | `org_id`, `user_id` (nullable), `action`, `resource_type`, `resource_id`, `entry_metadata` (JSON) |
| `BusinessRule` | `business_rules` | `version_id`, `rule_type`, `title`, `config` (JSON), `created_by` |
| `CMDBConfig` | `cmdb_configs` | `org_id`, `lookup_url_template`, `auth_header_name`, `encrypted_auth_header_value`, `owner_json_path`, `criticality_json_path` |
| `CredentialSet` | `credential_sets` | `version_id`, `credential_type`, `encrypted_secret`, `login_endpoint`, `login_body_template`, `token_response_path`, `extra_cookies` (JSON) |
| `FindingTicket` | `finding_tickets` | `finding_id`→findings **CASCADE**, `ticketing_config_id`, `external_key`, `external_url` |
| `Finding` | `findings` | `scan_run_id`→scan_runs **CASCADE**, `agent_job_id`→agent_jobs **CASCADE**, `check_id`, `severity`, `owasp_2025_category`, `cwe_id`, `cvss_vector`/`cvss_score`, `affected_endpoints` (JSON), `confirmation_status`, `retest_status` |
| `Evidence` | `evidence` | `finding_id`→findings **CASCADE**, `request_raw`, `response_raw`, `screenshot_refs`, `payload` (nullable — the exact substring proving the finding, highlighted in reports, §9) |
| `LoginMacro` | `login_macros` | `version_id`, `credential_set_id`→credential_sets **CASCADE**, `steps` (JSON) |
| `NotificationConfig` | `notification_configs` | `org_id`, `provider`, `encrypted_webhook_url`, `notify_on_scan_completed` |
| `OidcProviderConfig` | `oidc_provider_configs` | `org_id`, `issuer`, `client_id`, `encrypted_client_secret`, `redirect_uri`, `default_role` |
| `OrgBranding` | `org_branding` | `org_id` (unique), `logo_object_key`, `company_name`, `primary_color_hex` |
| `Organization` | `organizations` | `name` (unique) |
| `User` | `users` | `org_id`, `email` (unique), `hashed_password`, `role`, `is_active`, `oidc_subject`, `invite_token` |
| `Project` | `projects` | `org_id`, `name`, `created_by`, `archived_at` |
| `Version` | `versions` | `project_id`, `name`, `created_by` |
| `ScopeEntry` | `scope_entries` | `version_id`, `host`, `port`, `path_pattern`, `in_scope`, `purpose` (`"target"` default or `"login_only"` — §5.5) |
| `RolePermission` | `role_permissions` | `role`, `resource`, `action`, `allowed` |
| `RetestJob` | `retest_jobs` | `finding_id`→findings **CASCADE**, `requested_by`, `status`, `result`, `request_raw`/`response_raw` |
| `ReviewCandidate` | `review_candidates` | `scan_run_id`→scan_runs **CASCADE**, `agent_job_id`→agent_jobs **CASCADE**, `check_type`, `severity_guess`, `llm_reasoning`, `llm_confidence`, `status` |
| `SamlConfig` | `saml_configs` | `org_id`, `idp_metadata_xml`, `idp_sso_url`, `idp_entity_id`, `idp_x509_cert` |
| `ScanRun` | `scan_runs` | `version_id`, `status`, `requested_by`, `error`, `warning`, `llm_cost_usd` (Numeric 10,4), `executive_summary`, `ai_provider_config_id` (nullable), `tech_stack_fingerprint` (JSON) |
| `AgentJob` | `agent_jobs` | `scan_run_id`→scan_runs **CASCADE**, `agent_type`, `status`, `stats` (JSON) |
| `Target` | `targets` | `version_id`, `host`, `port`, `base_url` |
| `TicketingConfig` | `ticketing_configs` | `org_id`, `provider`, `base_url`, `encrypted_api_token`, `project_key`, `issue_type` |
| `TrafficInteraction` | `traffic_interactions` | `version_id`, `credential_set_id`→credential_sets **SET NULL**, `source`, request/response fields, `timing_ms` |
| `VGSConfig` | `vgs_configs` | `org_id`, `encrypted_webhook_url`, `push_on_scan_completed`, `auth_type` (nullable), `encrypted_auth_value` (nullable) |
| `VgsVulnerabilityLibraryEntry` | `vgs_vulnerability_library` | `org_id`, `title`, `severity`, `cvss_score`/`vector`, `description`, `recommendation` |
| `VgsReportDraft` | `vgs_report_drafts` | `version_id` (unique), `app_title`, `scope`, `urls`, `findings_auto_seeded` |
| `VgsReportVulnerability` | `vgs_report_vulnerabilities` | `report_draft_id`→vgs_report_drafts **CASCADE**, `library_entry_id` (nullable), `source_finding_id`→findings **SET NULL**, `order_index` |
| `VgsEvidenceStep` | `vgs_evidence_steps` | `report_vulnerability_id`→vgs_report_vulnerabilities **CASCADE**, `step_order`, `screenshot_object_keys` (JSON) |

**`AuthorizationRecord`, referenced in the original design's guardrail #1,
does not exist in the current model set** — confirmed removed (§18).

---

## 16. Appendix — Full API Route Reference (30 modules)

| Module | Endpoints |
|---|---|
| `ai_provider_configs.py` | `POST /ai-provider-configs`, `GET /ai-provider-configs`, `POST /ai-provider-configs/{id}/set-default`, `DELETE /ai-provider-configs/{id}` |
| `api_keys.py` | `POST /api-keys`, `GET /api-keys`, `POST /api-keys/{id}/revoke` |
| `attack_chains.py` | `GET /scan-runs/{scan_run_id}/attack-chains` |
| `auth.py` | `POST /auth/register`, `POST /auth/login`, `GET /auth/me` |
| `browser_extension.py` | `GET /browser-extension/download` (zips `browser-extension/` on demand — see §13.3) |
| `burp.py` | `POST /burp/scans`, `POST /burp/scans/{task_id}/import` |
| `business_rules.py` | `POST /business-rules`, `GET /business-rules`, `DELETE /business-rules/{id}` |
| `cmdb_configs.py` | `POST /cmdb-configs`, `GET /cmdb-configs`, `DELETE /cmdb-configs/{id}`, `POST /cmdb-configs/{id}/lookup` |
| `credentials.py` | `POST /credentials`, `GET /credentials`, `PATCH /credentials/{id}`, `DELETE /credentials/{id}`, `POST /credentials/{id}/test-login`, `POST /credentials/{id}/record-macro/start`, `POST /credentials/{id}/record-macro/{recording_id}/finish`, `POST /credentials/{id}/record-macro/{recording_id}/cancel`, `GET /credentials/{id}/macros`, `DELETE /credentials/{id}/macros/{macro_id}` |
| `dashboard.py` | `GET /organizations/me/dashboard` |
| `finding_tickets.py` | `POST /findings/{id}/tickets`, `GET /findings/{id}/tickets` |
| `findings.py` | `PATCH /findings/{id}`, `DELETE /findings/{id}` |
| `macro_upload.py` | `POST /credentials/{credential_id}/macros/upload` |
| `notification_configs.py` | `POST /notification-configs`, `GET /notification-configs`, `DELETE /notification-configs/{id}`, `POST /notification-configs/{id}/test` |
| `objects.py` | `GET /objects/{key:path}` |
| `oidc.py` | `POST /oidc-provider-configs`, `GET /oidc-provider-configs`, `DELETE /oidc-provider-configs/{id}`, `GET /auth/oidc/{id}/login`, `GET /auth/oidc/callback` |
| `org_branding.py` | `GET /org-branding`, `PUT /org-branding`, `POST /org-branding/logo`, `DELETE /org-branding/logo` |
| `organizations.py` | `GET /organizations/me` |
| `projects.py` | `POST /projects`, `GET /projects`, `GET /projects/{id}`, `POST /projects/{id}/archive`, `POST /projects/{id}/unarchive`, `DELETE /projects/{id}` |
| `retest_jobs.py` | `POST /findings/{id}/retest`, `GET /findings/{id}/retest-jobs` |
| `review_candidates.py` | `GET /scan-runs/{id}/review-candidates`, `POST /review-candidates/{id}/promote`, `POST /review-candidates/{id}/dismiss` |
| `saml.py` | `POST /saml-configs`, `GET /saml-configs`, `DELETE /saml-configs/{id}`, `GET /saml-configs/{id}/metadata.xml`, `POST /saml-configs/{id}/idp-metadata` |
| `scans.py` | `POST /versions/{id}/scan-runs`, `POST /versions/{v}/scan-runs/{prior}/retest`, `GET /versions/{id}/scan-runs`, `GET /scan-runs/{id}`, `POST /scan-runs/{id}/cancel`, `DELETE /scan-runs/{id}`, `GET /scan-runs/{id}/findings`, `GET /scan-runs/{id}/report.{json,html,pdf,docx,csv,vgs.docx}`, `GET /scan-runs/{later}/diff/{earlier}` |
| `targets.py` | `POST /targets`, `GET /targets`, `DELETE /targets/{id}` |
| `ticketing_configs.py` | `POST /ticketing-configs`, `GET /ticketing-configs`, `DELETE /ticketing-configs/{id}` |
| `traffic_import.py` | `POST /traffic/import`, `POST /traffic/manual`, `GET /traffic` |
| `users.py` | `POST /users/invite`, `GET /users`, `POST /users/accept-invite`, `POST /users/{id}/deactivate`, `POST /users/{id}/reactivate` |
| `versions.py` | `POST /projects/{id}/versions`, `GET /projects/{id}/versions`, `GET /versions/{id}`, `POST /versions/{id}/scope-entries`, `GET /versions/{id}/scope-entries`, `PATCH /versions/{id}/scope-entries/{entry_id}`, `DELETE /versions/{id}/scope-entries/{entry_id}` |
| `vgs_configs.py` | `POST /vgs-configs`, `GET /vgs-configs`, `DELETE /vgs-configs/{id}`, `POST /vgs-configs/{id}/test` |
| `vgs_vulnerabilities.py` | **library_router** (`/vgs-vulnerability-library`): `POST`, `GET`, `PATCH /{id}`, `DELETE /{id}`, `POST /load-from-portswigger`. **draft_router** (`/versions/{id}/vgs-report-draft`): `GET`, `PATCH`, `POST /vulnerabilities`, `GET /vulnerabilities`, `GET /available-findings`, `POST /vulnerabilities/from-finding/{id}`, `PATCH /vulnerabilities/{id}`, `DELETE /vulnerabilities/{id}`, `POST/GET/PATCH/DELETE /vulnerabilities/{id}/evidence-steps[/{step_id}]`, `POST .../screenshots`, `GET /report.docx` |

---

## 17. Appendix — Full Check Catalog (39 static IDs + dynamic IDs)

| Catalog file | Check IDs (severity / CWE) |
|---|---|
| `catalog.yaml` (15 checks) | `missing-hsts` (Low/319), `missing-csp` (Low/693), `missing-x-frame-options` (Medium/1021), `missing-x-content-type-options` (Low/693), `missing-referrer-policy` (Low/200), `missing-permissions-policy` (Low/693), `cookie-missing-secure` (Medium/614), `cookie-missing-httponly` (Medium/1004), `cookie-missing-samesite` (Low/1275), `server-version-disclosure` (Low/200), `verbose-error-stack-trace` (Medium/209), `directory-listing-enabled` (Medium/548), `plaintext-http` (High/319), `weak-tls-version` (Medium/326), `autocomplete-enabled-password-field` (Low/522) |
| `auth_catalog.yaml` | `jwt-alg-none` (Critical/347), `jwt-missing-expiration` (Medium/613), `jwt-alg-confusion` (Critical/347), `jwt-weak-signing-secret` (Critical/330), `weak-session-token-entropy` (Medium/330) |
| `cache_poisoning_catalog.yaml` | `web-cache-poisoning-unkeyed-input` (High/441), `web-cache-deception` (High/524) |
| `clickjacking_catalog.yaml` | `clickjacking-confirmed` (Medium/1021) |
| `cors_catalog.yaml` | `cors-reflected-origin-with-credentials` (Critical/942), `cors-wildcard-origin` (Low/942) |
| `csrf_catalog.yaml` | `csrf-missing-protection` (High/352) |
| `csv_injection_catalog.yaml` | `csv-formula-injection` (Medium/1236) |
| `file_upload_catalog.yaml` | `file-upload-insufficient-validation` (High/434), `file-upload-image-polyglot-bypass` (Medium/434) |
| `graphql_catalog.yaml` | `graphql-introspection-enabled` (Medium/200) |
| `host_header_catalog.yaml` | `host-header-injection` (Medium/346) |
| `oauth_catalog.yaml` | `oauth-redirect-uri-validation-bypass` (Critical/601) |
| `request_smuggling_catalog.yaml` | `potential-http-request-smuggling` (High/444) |
| `session_invalidation_catalog.yaml` | `session-not-invalidated-on-logout` (High/613) — moved out of `auth_catalog.yaml`; `SessionInvalidationAgent` (§5.5) is the sole implementation now |
| `ssrf_catalog.yaml` | `ssrf-confirmed` (Critical/918) |
| `vulnerable_components_catalog.yaml` | `vulnerable-client-side-component` (High/1104) |
| `weak_password_policy_catalog.yaml` | `weak-password-policy-accepted` (Medium/521) |
| `websocket_catalog.yaml` | `websocket-missing-origin-validation` (High/346) |
| `xxe_catalog.yaml` | `xxe-file-disclosure` (High/611) |

**Dynamically-generated check IDs** (emitted directly by agent code, not
YAML-backed): `sqli-error`, `sqli-boolean`, `command-injection`, `ssti`,
`path-traversal`, `nosql-injection` (`injection.py`); `xss-reflected`
(`xss.py`); `dom-xss-fragment` (`dom_xss.py`); `xss-stored`
(`stored_xss.py`); `client-side-prototype-pollution`
(`prototype_pollution.py`); `potential-insecure-deserialization`
(`deserialization.py`); `access-control-{comparison_type}`
(`access_control.py`); `business-logic-{rule_type}` (`business_logic.py`).

---

## 18. Appendix — Spec vs. Reality: The Complete, Honest Delta

Read against the original `docs/BUILD_SPEC.md` in full. This is not a
list of bugs — it's an honest accounting of where deliberate build
decisions diverged from the original design, in both directions.

**Built less than originally specified:**

1. **Authorization gate — removed entirely.** The spec's guardrail #1
   required a recorded authorization (uploaded letter/attestation) before
   any active testing could run. `AuthorizationRecord` was built, then
   fully removed (migration `0022_drop_authorization_records.py`) — no
   model, route, or frontend tab references it today. Scope enforcement
   (the other half of that guardrail) remains fully real and enforced.
2. **Human-in-the-loop approval checkpoints — not built.** No code exists
   for configurable manual-approval gates before injection payloads or
   state-changing business-logic tests run.
3. **Smart Scan cost-optimization routing — only one narrow case built.**
   See §2.1: the fingerprint is computed and shown, but doesn't gate
   scheduling anywhere except one SSTI check.
4. **Depth slider (Quick/Standard/Deep/Deep-Paranoid) — not built.** No
   such setting, enum, or UI control exists anywhere in the codebase.
5. **Cross-credential-set result caching — not built.** The spec called for
   deduplicating identical endpoint+parameter tests across credential sets.
   The dedup that does exist (clickjacking, cache_poisoning, dom_xss,
   prototype_pollution) is narrower — one check per distinct host within a
   single run, not across credential sets.
6. **Orchestration engine — LangGraph, not Temporal.io.** The spec offered
   both, with Temporal.io as the primary recommendation; the lighter-weight
   LangGraph option was the one actually built. No Temporal references
   exist anywhere in the codebase.

**Built beyond what was originally specified:**

7. **VGS integration — both spec-recommended paths, plus a full native
   workspace, plus a third export mode.** The spec recommended starting
   with webhook push alone; the native report-builder port (its own
   top-level frontend workspace) and a no-curation-needed per-scan-run
   VGS-format export were both built in addition (§10).
8. **The image-polyglot file-upload bypass technique** — not mentioned in
   the spec at all.
9. **The PortSwigger Web Security Academy scraper** ("Load from
   PortSwigger") — not in the spec.
10. **UI-only, per-org default AI provider configuration**
    (`AIProviderConfig.is_default` + the Account-page "Set as default"
    control) — the spec described the adapter interface but not a
    UI-driven default-selection mechanism.
11. **A genuine conversational Microsoft Teams bot** — the spec's
    integration section called for a generic notification adapter only,
    not an interactive bot with real command parsing.
12. **Two independent ways to record a login macro, not just one.** The
    spec called for "a Playwright-backed in-browser recorder" without
    specifying delivery. What's built: a real headed Chromium, streamed
    live into the Verdikt UI itself over VNC (Xvfb/x11vnc/noVNC) so no
    local display or browser extension is needed when running via Docker
    — plus, since neither outcome is available in a manual/native (no
    Docker) setup, a genuinely separate standalone browser extension
    (`browser-extension/`) producing the identical macro JSON shape,
    downloadable in one click from the same UI.
13. **Four scanner checks ported from a sibling DAST project, beyond the
    spec's own check list** — Weak Password Policy, CSV/Formula Injection,
    Known Vulnerable Components, and a hardened rebuild of Failure to
    Invalidate Session on Logout (§5.1, §7).

**Matches the spec closely:**

14. The AI Provider Abstraction itself, including the exact
    `CustomEndpointAdapter` concept the spec named by placeholder
    (implemented as `GenericOpenAIAdapter`).
15. RBAC roles (Org Admin / Project Lead / Analyst / Client-Viewer) match
    the spec exactly, modeled as a real permission-matrix table as the
    spec explicitly instructed, not hardcoded checks.
16. CMDB integration exists, implemented as a single concrete,
    vendor-agnostic REST client rather than the spec's sketched abstract
    per-vendor interface — a deliberate substitution, since there's no one
    real CMDB API to build and test against honestly.
17. **Per-task-type model routing — built on the second attempt.** The spec
    called for cheap models on recon/header checks and frontier models
    reserved for business-logic reasoning (`docs/BUILD_SPEC.md`'s own
    words: "cheap/fast models handle recon, header/config checks, and
    pattern-matching... reserve frontier-tier models for business-logic
    reasoning, multi-step exploit chains, and final report narrative").
    The first attempt — `app.ai.model_routing`, a `ModelRouter` with
    per-agent-role tiers and an Account-page UI to configure them
    (migration `0029_ai_provider_config_model_tiers`) — was deliberately
    removed again (migration `0032_drop_ai_provider_model_tiers`) once it
    added real configuration-surface complexity (extra model names an
    analyst had to correctly fill in per provider config) without a
    correspondingly clear benefit. `app.ai.model_tiers` (§6.2) is the
    second attempt, structurally different in the one way that mattered:
    zero new database columns, zero new UI, nothing for an analyst to
    configure or get wrong. An org still configures exactly one model;
    the backend silently substitutes a same-family sibling for the small
    set of tasks the spec called out as disproportionately cheap or
    expensive, and falls back to that one configured model, unchanged,
    for anything it doesn't recognize.

---

## 19. Appendix — AI Provider & Configuration Reference

| Setting | Default | Purpose |
|---|---|---|
| `database_url` | `postgresql+psycopg://verdikt:verdikt@localhost:5432/verdikt` | Postgres connection |
| `frontend_origin` | `http://localhost:5173` | CORS allow-list origin |
| `jwt_secret` / `jwt_algorithm` / `jwt_expire_minutes` | — / `HS256` / 720 | Auth token config |
| `vault_master_key` | dev placeholder | Fernet key for `LocalKMSAdapter` |
| `kms_provider` | `local` | `local` or `aws` |
| `object_storage_root` / `object_storage_provider` | `./data/objects` / `local` | Local disk or `s3` |
| `ai_provider` | `fake` | Deployment-wide default: `claude` / `openai` / `custom` / `fake` |
| `ai_model` | `claude-haiku-4-5` | Deployment-wide default model |
| `anthropic_api_key` / `openai_api_key` | None | Named-provider API keys |
| `custom_llm_base_url` / `custom_llm_api_key` / `custom_llm_auth_type` | None / None / `bearer_token` | In-house/self-hosted LLM config |
| `max_llm_cost_usd_per_scan` | **2.00** | Hard per-scan LLM spend cap (§6.1) |
| `ssrf_callback_host` | None (auto-detect) | Host the target calls back to for SSRF OOB proof |

Note: Gemini and Grok have **no** `.env` settings — reachable only via a
per-org `AIProviderConfig` in the UI.

Note: model tiering (§6.2) has **no setting or column of its own anywhere
in this table or the database** — it's a pure function
(`resolve_tiered_model()`) applied on top of whichever model resolution
above already produced, for a fixed set of call sites in `graph.py` /
`runner.py` / `scans.py`. There is nothing here for an operator or analyst
to configure.

---

## 20. Appendix — Migration History (36 files, one linear chain)

`0001_initial_schema` → `0001b_widen_alembic_version_column` (widens
`alembic_version.version_num` for this project's long revision slugs) →
`0002_scan_findings_and_permissions` → `0003_phase2_review_candidates_and_login_config`
→ `0004_phase3_business_rules` → `0005_phase4_login_macros` →
`0006_phase5_executive_summary` → `0007_phase6_ai_provider_configs` →
`0008_phase6b_oidc_sso` → `0009_phase6c_api_keys` →
`0010_phase8_retest_jobs` → `0011_phase9_ticketing_and_notifications` →
`0012_phase10_cmdb_and_vgs` → `0013_credential_extra_cookies` →
`0014_phase11_extensibility_and_lifecycle` → `0015_saml_org_config` →
`0016_org_branding` → `0017_vgs_report_builder` →
`0018_scan_delete_cascade_and_vgs_finding_link` →
`0019_vgs_evidence_cascade_and_auto_seed` → `0020_scan_run_warning` →
`0021_credential_set_delete_cascade` → `0022_drop_authorization_records`
(drops the table entirely) → `0023_ai_provider_config_default` →
`0024_spark_app_id_and_secondary_key` → `0025_scan_run_token_usage` →
`0026_finding_resource_permissions` → `0027_business_rule_source` →
`0028_credential_privilege_rank` → `0029_ai_provider_config_model_tiers` →
`0030_ai_provider_config_secret_rotated_at` →
`0031_drop_spark_specific_columns` → `0032_drop_ai_provider_model_tiers` →
`0033_vgs_auto_seed_finding_memory` → `0034_scope_entry_purpose` →
`0035_evidence_payload`.

Two of these pairs are worth reading together, not in isolation: `0024`
added columns for a since-removed, org-specific internal LLM gateway
integration (never a general-purpose feature, and out of scope once that
org's need went away); `0031` drops them. `0029` added per-agent-role model
tiering (`model_reasoning`/`model_classification` columns, letting an org
route different agents to different models); `0032` drops it, in favor of
the single-configured-model design described in §1/§6 — real functionality
that shipped, was used, and was deliberately simplified back out once it
proved to be complexity without enough benefit, not a mistake papered over
(§6.2/§18 item 17 covers the second, schema-free attempt that replaced it).
`0033` tracks a persistent `auto_seeded_finding_ids` column on
`VgsReportDraft` (§10) that records every `Finding.id` an auto-seed pass
has ever offered a report draft, independent of whether the resulting
vulnerability still exists in the draft. `0034` and `0035` are the newest:
`scope_entries.purpose` (`"target"` vs. `"login_only"`, §5.5's IdP
scope-leak fix) and `evidence.payload` (§9's highlighted-substring
evidence), both additive and nullable/defaulted, so neither required a
backfill.

---

## 21. Appendix — RBAC Matrix

**20 resources**: `organization`, `project`, `version`, `target`,
`credential`, `traffic`, `scan`, `finding`, `review_candidate`, `business_rule`,
`ai_provider_config`, `oidc_provider_config`, `notification_config`,
`ticketing_config`, `cmdb_config`, `vgs_config`, `user`, `org_branding`,
`saml_config`, `vgs_vulnerability` — each with `create`/`read`/`update`/`delete`.

| Role | Access pattern |
|---|---|
| `org_admin` | Full CRUD on all 20 resources |
| `project_lead` | Full CRUD on engagement resources; read-only on `organization`; no access to `user` management |
| `analyst` | Read on everything, plus `create` on `traffic`/`scan`/`business_rule`, `update` on `review_candidate` |
| `viewer` | Read-only on everything |

---

## 22. Appendix — Frontend Route & Page Map

```
/login, /register, /accept-invite, /oidc-callback   (public)
Protected (behind Layout):
  /                          → ProjectsPage
  /dashboard                 → DashboardPage
  /projects/:projectId       → ProjectDetailPage
  /versions/:versionId       → VersionDetailPage
  /scan-runs/:scanRunId      → ScanRunDetailPage
  /vgs                       → VgsLandingPage
  /vgs/:versionId            → VgsWorkspacePage
  /account                   → AccountPage
```

- **Account page sections** (own file each): Branding, CMDB Configs,
  Notification Configs, SAML Configs, Ticketing Configs, Users, VGS
  Configs. (AI Provider Configs remains inline in `AccountPage.tsx`.)
- **Scan Run detail tabs**: Agent Jobs, Diff, Findings, Reports, Review
  Candidates, Site Map, Ticket.
- **Version detail tabs**: Burp, Business Rules, Credentials, Macro
  Recording, Scan Runs, Scope, Targets, Traffic — plus dedicated
  business-rule sub-forms (Credential Select, HTTP Method Select,
  Price/Quantity Tampering, Race Condition, Resource Isolation, Workflow
  Order) and VGS report sub-tabs (Evidence, Generate, Project Info,
  Vulnerabilities).
- **API client**: `src/api/client.ts` exposes 23 namespaced sub-objects
  (auth, organizations, projects, users, versions, targets, credentials,
  businessRules, scanRuns, retestJobs, reviewCandidates, apiKeys,
  aiProviderConfigs, traffic, burp, notificationConfigs, ticketingConfigs,
  findingTickets, cmdbConfigs, vgsConfigs, samlConfigs, orgBranding,
  attackChains, oidcProviderConfigs); `src/api/types.ts` defines 62
  exported types.

---

## 23. What's Next

Natural next steps, informed directly by the delta in §18:

- Building out the Smart Scan graph-level routing the original design
  called for — using the tech-stack fingerprint to actually skip
  irrelevant node scheduling, not just display it.
- A depth/intensity profile (Quick/Standard/Deep) as a scan-trigger option.
- Extending `app.ai.model_tiers`'s family table to Gemini once Google's
  3.x naming settles past the October 2026 retirement of the 2.5 line
  (§6.2, §18 item 17) — deliberately deferred rather than shipping a
  guessed model id.
- A more sophisticated file-upload bypass technique (JPEG polyglot, or
  chaining an accepted upload with a discovered local-file-inclusion
  vector for standalone RCE proof).
- Configurable human-in-the-loop approval checkpoints for the more
  invasive check categories, as originally specified.

---

## 24. Frequently Asked Questions

Real, recurring questions from people using or evaluating Verdikt. The
full version, kept up to date independently of this document's release
cadence, lives at [`docs/FAQ.md`](../FAQ.md) — if the two ever disagree,
that file is the source of truth.

**How does the crawl/spider work?** `ReconAgent` (§5, `app/agents/recon.py`)
runs a bounded, same-origin, breadth-first crawl (300 pages / depth 6 by
default, both configurable), and runs it **twice** — once unauthenticated,
once fully authenticated once `login` succeeds — because a pre-login-only
crawl was found live to discover exactly one form, the login page's own.
Every request is scope-checked by `ScopedHttpClient`; redirects are queued
as their own frontier entries rather than auto-followed; a Logout link is
deliberately never clicked during this crawl (it would kill the one shared
session every other concurrent agent depends on) — it's instead captured
separately as a `discovered_logout_urls` entry, specifically so
`session_invalidation` (§5.1, §7) has a real logout URL to test against,
via its own dedicated, disposable login rather than the shared session.
`recon_planner` (§5.1a) then runs up
to two propose-then-crawl rounds over the resulting site map: each round's
AI pass suggests additional plausible-but-unlinked paths, every suggestion
is verified with a real request before it counts for anything, and
whatever resolves is crawled from — not just added as a single URL — so
anything reachable from a confirmed suggestion (an admin panel's own nav,
say) gets discovered too.

**How is a vulnerability actually identified, and what does AI do?** Every
check runs the same four-stage pipeline in §5.3: a deterministic probe
(judged by a fixed, non-AI signal) → LLM triage → deterministic
re-execution → adversarial LLM validation. AI never originates a finding
from nothing — every model call takes an already-gathered deterministic
artifact as its input, and a "vulnerable" verdict still has to survive a
fresh, real re-execution before anything else happens to it. Beyond
judgment calls on ambiguous evidence, AI's two other roles are generating
extra, tech-stack-aware payloads once per scan (never trusted more than a
fixed payload — a bad suggestion just never trips the shared deterministic
signal) and proposing business-logic/IDOR test hypotheses no fixed pattern
could cover (`business_logic_planner.py`'s own docstring: *"proposes what
to test and how, never whether something IS vulnerable"*).

**How is this different from WebInspect, Checkmarx, etc.?** Checkmarx is
SAST (static source analysis, no running application) — a different
category entirely. WebInspect is the fair DAST-to-DAST comparison: the
real differences are Confirmed-Only output instead of a flat
potential-findings dump requiring full manual triage, first-class
business-logic/IDOR coverage via AI hypothesis generation plus a full
identity/privilege matrix, automatic attack-chain synthesis (§8) instead of leaving
that connective work to the reader, a recorded-and-replayed login macro
instead of silently going unauthenticated on session expiry, and native
downstream-workflow integrations (§9–§11) rather than just a report file.
The honest tradeoff: every AI-triaged check costs real, capped time and
money a purely deterministic scanner wouldn't spend.

**If I upload a traffic file, does it only audit that, or crawl the live
site too?** Both, combined into one crawl, never either/or. Imported
traffic (HAR/Burp/Postman/Zest/OpenAPI, or one pasted request) is read
before the crawl starts and fed in as extra frontier seeds — exactly like
the target's own homepage already is (`app/agents/traffic_seed.py`,
wired into `recon_node`). The crawler then also follows links reachable
*from* those imported URLs, and the live crawl always runs regardless of
what — or whether — anything was imported. This is what makes a
client-rendered SPA's real API surface testable at all.

**What's the architecture, and what's AI's role given deterministic
scanning is already in place?** One scan compiles and executes the
31-node DAG in §5.1 — real parallel fan-out, not a sequential loop — with
`chain_analysis` reviewing the complete set of that run's Confirmed
findings once everything else is done. The division of labor: a
deterministic signal is evidence, not a verdict — it establishes *that*
something is worth asking about, but not *whether* it means anything in
context. AI's output is never trusted outright; it's gated by more
determinism at every step (re-execution, adversarial validation, the same
detection pipeline an analyst's own hand-typed business rule goes through).
A finding only exists where both layers agree, twice.

---

*This document reflects the system exactly as implemented, verified
directly against the codebase. Architecture diagrams are provided
separately as Mermaid (`.mmd`) source files, directly importable into
Miro's Mermaid-import feature.*
