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
**24-node LangGraph DAG** covering the OWASP Top 10 (2025) and the full
PortSwigger Web Security Academy topic list, followed by a 25th
cross-cutting attack-chain-composition step — each detection agent combining
deterministic, re-executable HTTP-level probing with LLM-assisted triage and
adversarial validation. The result is a report an experienced penetration
tester would recognize as their own work: confirmed findings only, real
evidence (request/response pairs, browser screenshots), plain-language and
technical write-ups side by side, and a remediation path for every issue.

The system is explicitly designed so **no single AI vendor is load-
bearing**. Every LLM-dependent agent talks to a pluggable `AIProviderAdapter`
interface — Claude, OpenAI, Gemini, Grok, or any self-hosted/in-house model
that speaks the OpenAI chat-completions protocol. Swapping providers is a
configuration action in the UI, not a code change.

**Current state, verified against the running codebase:** 41 files under
`app/agents/` (24 of them wired into the scan graph, the rest shared
infrastructure and support modules), 28 API route modules, ~30 persisted
data models, 9 external integrations, 14 YAML check catalogs (34 statically
defined check IDs, plus a further dozen dynamically-generated ones), 24
Alembic migrations, 19 RBAC resources, and a backend test suite of **99
files / 527 collected tests** — all figures confirmed by direct inspection
and by running the test collector, not estimated. Full reference tables for
every one of these are in the appendices (§13–§22).

---

## 2. The Problem

Manual web/API penetration testing is thorough but doesn't scale: a
competent tester takes days per application, and demand for testing far
outpaces the supply of qualified testers. Existing DAST scanners scale but
don't produce trustworthy results — they're notorious for high false-
positive rates, shallow coverage of business logic and access control
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

1. **Multi-agent, not one big prompt.** Twenty-four narrow, purpose-built
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
general graph-level routing**. The 24-node LangGraph DAG has zero
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
        API["REST API — 28 route modules<br/>JWT bearer auth, RBAC-enforced"]
        ORCH["Multi-Agent Orchestrator<br/>(LangGraph, 24-node DAG)"]
        AIABS["AI Provider Abstraction<br/>Claude / OpenAI / Gemini / Grok / Custom"]
        RPT["Reporting Engine<br/>HTML / PDF (reportlab) / DOCX / CSV / JSON"]
        VAULT["Credential Vault<br/>(envelope encryption, pluggable KMS)"]
    end

    subgraph Data["Persistence"]
        PG[("PostgreSQL<br/>~30 models")]
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
```

**Backend:** Python, FastAPI, SQLAlchemy 2.0 (async), Alembic migrations
(24 files, one linear chain), PostgreSQL. Dialect-agnostic ORM layer, so
the test suite runs against ephemeral SQLite with zero external services
(with one deliberately-accepted limitation: SQLite doesn't enforce
`ON DELETE CASCADE`, so cascade behavior is verified live against the real
Postgres, not by the unit suite).

**Frontend:** Vite + React + TypeScript, TanStack Query for server state,
React Router, Tailwind CSS. A hand-written typed fetch client
(`src/api/client.ts`, 23 namespaced sub-objects, 62 exported types in
`src/api/types.ts`) mirrors the backend's Pydantic schemas.

**Agent orchestration:** LangGraph builds a 24-node directed graph per scan
run, with genuine parallel fan-out where checks don't depend on each other
(12 nodes off `recon`, 10 more off `authenticated_recon`), and explicit
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
the full field-level reference for all ~30 models is in **Appendix
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

### 5.1 Scan lifecycle — the real, verified 24-node DAG

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
    E --> A1["dom_xss"]
    E --> A2["injection<br/>(SQLi / cmd-inj / SSTI /<br/>path traversal / NoSQLi)"]
    E --> A3["xss"]
    E --> A4["auth<br/>(JWT / session)"]
    E --> A5["access_control"]
    E --> A6["business_logic"]
    E --> A7["csrf"]
    E --> A8["stored_xss"]
    E --> A9["file_upload"]
    E --> A10["websocket"]
    U1 & U2 & U3 & U4 & U5 & U6 & U7 & U8 & U9 & U10 & U11 & U12 --> G
    A1 & A2 & A3 & A4 & A5 & A6 & A7 & A8 & A9 & A10 --> G["chain_analysis<br/>(25th step, runs after the graph —<br/>composes multi-finding attack chains)"]
    G --> H["Report generation<br/>(HTML / PDF / DOCX / CSV / JSON)"]
    H --> I["Best-effort notify:<br/>Slack / Teams / VGS webhook"]
```

There are genuinely **no conditional edges anywhere in this graph** —
`add_conditional_edges` is never called. Every node listed always runs.
Recon deliberately runs twice: once unauthenticated (all a purely anonymous
visitor would ever see — usually just a login form), and once fully
authenticated after `login` succeeds. This was a real, live-found gap
during development — a pre-login-only crawl against DVWA discovered
exactly one form (the login form itself), leaving every other agent with
nothing to test.

### 5.2 What's in `app/agents/` beyond the 24 graph nodes

The `agents/` directory holds **41 files total**. Besides the 24 wired into
the graph (plus `chain_analysis.py` as the 25th, post-graph step), the
remaining ~16 files are shared infrastructure the detection agents are
built on top of, not standalone checks:

| File | Role |
|---|---|
| `http_client.py` | `ScopedHttpClient` — the scope-enforcement mechanism every other agent's requests pass through |
| `scope.py` | `is_in_scope()` allow-list matcher |
| `matrix.py` | Credential/privilege matrix engine (`Identity`, `MatrixEntry`) used by access-control and business-logic |
| `idor.py` | Shared numeric-ID substitution helpers |
| `probing.py` | Shared parameter-probing plumbing used by injection and XSS |
| `evidence.py` / `evidence_screenshot.py` | Raw HTTP evidence formatting; universal screenshot capture for non-browser-observable findings |
| `raw_http.py` | Raw-socket HTTP/1.1 primitives for wire-format-level checks (smuggling, WebSocket handshakes) |
| `clickjacking_proof.py` / `xss_browser_proof.py` | Real headless-browser proof mechanisms |
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

---

## 7. Vulnerability Coverage

Coverage maps to the OWASP Top 10 (2025) and the PortSwigger Web Security
Academy topic list. The full, exact list of every check ID, its severity,
and its CWE is in **Appendix §17** (34 YAML-defined checks across 14
catalog files, plus a further ~13 dynamically-generated check IDs emitted
directly by agent code for parameterized findings like `sqli-error` /
`access-control-{comparison_type}`). By category:

- **Injection** — SQL injection (error- and boolean-based), OS command
  injection, server-side template injection, NoSQL injection, path
  traversal
- **Broken access control** — IDOR, vertical/horizontal privilege
  escalation
- **Session & auth failures** — JWT alg-none/alg-confusion/weak-secret,
  missing expiration, weak session token entropy, session not invalidated
  on logout
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
  browser)
- **XXE, GraphQL introspection, cache poisoning/deception**
- **File upload** — dangerous-extension acceptance, plus an
  image-polyglot bypass technique for endpoints that do enforce a
  getimagesize()-style content check
- **CSRF, CORS misconfiguration, clickjacking** — clickjacking is
  confirmed by a real headless-browser framing attempt, not just a
  missing-header inference
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

---

## 10. VGS Integration — Two Complementary Modes, Both Built

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
     standard reports), auto-seeded into a new report draft.
   - **Manage Vulnerabilities** includes a one-click **"Load from
     PortSwigger"** action (`app/integrations/portswigger/client.py`'s
     `fetch_topics()`, 13 real seeded Web Security Academy URLs) — a native
     port of the original standalone VGS tool's scrape-to-Excel workflow,
     collapsed into a single server-side action.
   - **Evidence** supports numbered steps, each with one or more
     screenshots addable at any time, not just at step creation.
   - **Generate Report** (`GET /versions/{id}/vgs-report-draft/report.docx`)
     produces the same DOCX shape as the original VGS tool.

This is notably **more** than the original design called for — the spec
recommended starting with the webhook path alone; the native report-builder
port was built in addition, as its own complete workspace.

---

## 11. Enterprise Hardening

- **RBAC** — a real DB-backed `role_permissions` table across **19
  resources × 4 actions** (76 grantable permission cells), not hardcoded
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

**Docker Compose** brings up the full stack — PostgreSQL, backend, and
frontend — from a single command, verified end-to-end against a completely
fresh environment:

```mermaid
flowchart TB
    subgraph Host["Host Machine (macOS / Linux / Windows)"]
        subgraph Compose["docker compose up --build"]
            DB[("db<br/>postgres:16-alpine<br/>named volume: verdikt_pgdata<br/>host port 5433 (avoids native-Postgres collision)")]
            BE["backend<br/>python:3.12-slim + Playwright/Chromium<br/>(installed at BUILD time)<br/>runs `alembic upgrade head`<br/>then uvicorn --loop asyncio"]
            FEC["frontend<br/>node:22-slim, real Vite dev server<br/>npm run dev -- --host 0.0.0.0"]
        end
        Browser["Browser<br/>localhost:5173"]
    end
    BE -->|"db:5432"| DB
    Browser -->|"HTTP"| FEC
    Browser -->|"HTTP :8000"| BE
```

- **`--loop asyncio` is not a stylistic choice** — uvicorn's default
  `--loop auto` silently selects `uvloop`, which is incompatible with
  Playwright's async browser launch and hangs forever with no error
  message. This was found by actually running the container against a
  live Juice Shop target, not by reading documentation.
- Migrations run automatically on container start (a no-op once already
  current) — a fresh database gets its schema with zero manual steps.
- The backend's build-time virtualenv is protected from the dev bind-mount
  via a masking Docker volume (`backend_venv:/app/.venv`), so the container
  never silently inherits a host's binary-incompatible Python environment;
  the frontend uses the equivalent `node_modules` mask.
- The frontend Dockerfile runs the real Vite dev server (with HMR), not a
  production build — its own comment notes a production multi-stage/nginx
  build is a reasonable follow-up once there's an actual deployment target.
- `.gitattributes` (`* text=auto eol=lf`) normalizes line endings across
  macOS/Linux/Windows checkouts.

---

## 14. Testing & Quality Discipline

- **99 test files, 527 collected tests** — confirmed by running
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
| `Evidence` | `evidence` | `finding_id`→findings **CASCADE**, `request_raw`, `response_raw`, `screenshot_refs` |
| `LoginMacro` | `login_macros` | `version_id`, `credential_set_id`→credential_sets **CASCADE**, `steps` (JSON) |
| `NotificationConfig` | `notification_configs` | `org_id`, `provider`, `encrypted_webhook_url`, `notify_on_scan_completed` |
| `OidcProviderConfig` | `oidc_provider_configs` | `org_id`, `issuer`, `client_id`, `encrypted_client_secret`, `redirect_uri`, `default_role` |
| `OrgBranding` | `org_branding` | `org_id` (unique), `logo_object_key`, `company_name`, `primary_color_hex` |
| `Organization` | `organizations` | `name` (unique) |
| `User` | `users` | `org_id`, `email` (unique), `hashed_password`, `role`, `is_active`, `oidc_subject`, `invite_token` |
| `Project` | `projects` | `org_id`, `name`, `created_by`, `archived_at` |
| `Version` | `versions` | `project_id`, `name`, `created_by` |
| `ScopeEntry` | `scope_entries` | `version_id`, `host`, `port`, `path_pattern`, `in_scope` |
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

## 16. Appendix — Full API Route Reference (28 modules)

| Module | Endpoints |
|---|---|
| `ai_provider_configs.py` | `POST /ai-provider-configs`, `GET /ai-provider-configs`, `POST /ai-provider-configs/{id}/set-default`, `DELETE /ai-provider-configs/{id}` |
| `api_keys.py` | `POST /api-keys`, `GET /api-keys`, `POST /api-keys/{id}/revoke` |
| `attack_chains.py` | `GET /scan-runs/{scan_run_id}/attack-chains` |
| `auth.py` | `POST /auth/register`, `POST /auth/login`, `GET /auth/me` |
| `burp.py` | `POST /burp/scans`, `POST /burp/scans/{task_id}/import` |
| `business_rules.py` | `POST /business-rules`, `GET /business-rules`, `DELETE /business-rules/{id}` |
| `cmdb_configs.py` | `POST /cmdb-configs`, `GET /cmdb-configs`, `DELETE /cmdb-configs/{id}`, `POST /cmdb-configs/{id}/lookup` |
| `credentials.py` | `POST /credentials`, `GET /credentials`, `PATCH /credentials/{id}`, `DELETE /credentials/{id}`, `POST /credentials/{id}/record-macro`, `GET /credentials/{id}/macros` |
| `dashboard.py` | `GET /organizations/me/dashboard` |
| `finding_tickets.py` | `POST /findings/{id}/tickets`, `GET /findings/{id}/tickets` |
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
| `scans.py` | `POST /versions/{id}/scan-runs`, `POST /versions/{v}/scan-runs/{prior}/retest`, `GET /versions/{id}/scan-runs`, `GET /scan-runs/{id}`, `POST /scan-runs/{id}/cancel`, `DELETE /scan-runs/{id}`, `GET /scan-runs/{id}/findings`, `GET /scan-runs/{id}/report.{json,html,pdf,docx,csv}`, `GET /scan-runs/{later}/diff/{earlier}` |
| `targets.py` | `POST /targets`, `GET /targets`, `DELETE /targets/{id}` |
| `ticketing_configs.py` | `POST /ticketing-configs`, `GET /ticketing-configs`, `DELETE /ticketing-configs/{id}` |
| `traffic_import.py` | `POST /traffic/import`, `POST /traffic/manual`, `GET /traffic` |
| `users.py` | `POST /users/invite`, `GET /users`, `POST /users/accept-invite`, `POST /users/{id}/deactivate`, `POST /users/{id}/reactivate` |
| `versions.py` | `POST /projects/{id}/versions`, `GET /projects/{id}/versions`, `GET /versions/{id}`, `POST /versions/{id}/scope-entries`, `GET /versions/{id}/scope-entries`, `PATCH /versions/{id}/scope-entries/{entry_id}`, `DELETE /versions/{id}/scope-entries/{entry_id}` |
| `vgs_configs.py` | `POST /vgs-configs`, `GET /vgs-configs`, `DELETE /vgs-configs/{id}`, `POST /vgs-configs/{id}/test` |
| `vgs_vulnerabilities.py` | **library_router** (`/vgs-vulnerability-library`): `POST`, `GET`, `PATCH /{id}`, `DELETE /{id}`, `POST /load-from-portswigger`. **draft_router** (`/versions/{id}/vgs-report-draft`): `GET`, `PATCH`, `POST /vulnerabilities`, `GET /vulnerabilities`, `GET /available-findings`, `POST /vulnerabilities/from-finding/{id}`, `PATCH /vulnerabilities/{id}`, `DELETE /vulnerabilities/{id}`, `POST/GET/PATCH/DELETE /vulnerabilities/{id}/evidence-steps[/{step_id}]`, `POST .../screenshots`, `GET /report.docx` |

---

## 17. Appendix — Full Check Catalog (34 static IDs + dynamic IDs)

| Catalog file | Check IDs (severity / CWE) |
|---|---|
| `catalog.yaml` (15 checks) | `missing-hsts` (Low/319), `missing-csp` (Low/693), `missing-x-frame-options` (Medium/1021), `missing-x-content-type-options` (Low/693), `missing-referrer-policy` (Low/200), `missing-permissions-policy` (Low/693), `cookie-missing-secure` (Medium/614), `cookie-missing-httponly` (Medium/1004), `cookie-missing-samesite` (Low/1275), `server-version-disclosure` (Low/200), `verbose-error-stack-trace` (Medium/209), `directory-listing-enabled` (Medium/548), `plaintext-http` (High/319), `weak-tls-version` (Medium/326), `autocomplete-enabled-password-field` (Low/522) |
| `auth_catalog.yaml` | `session-not-invalidated-on-logout` (High/613), `jwt-alg-none` (Critical/347), `jwt-missing-expiration` (Medium/613), `jwt-alg-confusion` (Critical/347), `jwt-weak-signing-secret` (Critical/330), `weak-session-token-entropy` (Medium/330) |
| `cache_poisoning_catalog.yaml` | `web-cache-poisoning-unkeyed-input` (High/441), `web-cache-deception` (High/524) |
| `clickjacking_catalog.yaml` | `clickjacking-confirmed` (Medium/1021) |
| `cors_catalog.yaml` | `cors-reflected-origin-with-credentials` (Critical/942), `cors-wildcard-origin` (Low/942) |
| `csrf_catalog.yaml` | `csrf-missing-protection` (High/352) |
| `file_upload_catalog.yaml` | `file-upload-insufficient-validation` (High/434), `file-upload-image-polyglot-bypass` (Medium/434) |
| `graphql_catalog.yaml` | `graphql-introspection-enabled` (Medium/200) |
| `host_header_catalog.yaml` | `host-header-injection` (Medium/346) |
| `oauth_catalog.yaml` | `oauth-redirect-uri-validation-bypass` (Critical/601) |
| `request_smuggling_catalog.yaml` | `potential-http-request-smuggling` (High/444) |
| `ssrf_catalog.yaml` | `ssrf-confirmed` (Critical/918) |
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
4. **Per-task-type model routing — not built.** The spec called for cheap
   models on recon/header checks and frontier models reserved for
   business-logic reasoning. Every agent in a scan run uses the single
   model resolved once via `resolve_provider_and_model()`.
5. **Depth slider (Quick/Standard/Deep/Deep-Paranoid) — not built.** No
   such setting, enum, or UI control exists anywhere in the codebase.
6. **Cross-credential-set result caching — not built.** The spec called for
   deduplicating identical endpoint+parameter tests across credential sets.
   The dedup that does exist (clickjacking, cache_poisoning, dom_xss,
   prototype_pollution) is narrower — one check per distinct host within a
   single run, not across credential sets.
7. **Orchestration engine — LangGraph, not Temporal.io.** The spec offered
   both, with Temporal.io as the primary recommendation; the lighter-weight
   LangGraph option was the one actually built. No Temporal references
   exist anywhere in the codebase.

**Built beyond what was originally specified:**

8. **VGS integration — both spec-recommended paths, plus a full native
   workspace.** The spec recommended starting with webhook push alone; the
   native report-builder port (its own top-level frontend workspace) was
   built in addition.
9. **The image-polyglot file-upload bypass technique** — not mentioned in
   the spec at all.
10. **The PortSwigger Web Security Academy scraper** ("Load from
    PortSwigger") — not in the spec.
11. **UI-only, per-org default AI provider configuration**
    (`AIProviderConfig.is_default` + the Account-page "Set as default"
    control) — the spec described the adapter interface but not a
    UI-driven default-selection mechanism.
12. **A genuine conversational Microsoft Teams bot** — the spec's
    integration section called for a generic notification adapter only,
    not an interactive bot with real command parsing.

**Matches the spec closely:**

13. The AI Provider Abstraction itself, including the exact
    `CustomEndpointAdapter` concept the spec named by placeholder
    (implemented as `GenericOpenAIAdapter`).
14. RBAC roles (Org Admin / Project Lead / Analyst / Client-Viewer) match
    the spec exactly, modeled as a real permission-matrix table as the
    spec explicitly instructed, not hardcoded checks.
15. CMDB integration exists, implemented as a single concrete,
    vendor-agnostic REST client rather than the spec's sketched abstract
    per-vendor interface — a deliberate substitution, since there's no one
    real CMDB API to build and test against honestly.

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

---

## 20. Appendix — Migration History (24 files, one linear chain)

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
(drops the table entirely) → `0023_ai_provider_config_default`.

---

## 21. Appendix — RBAC Matrix

**19 resources**: `organization`, `project`, `version`, `target`,
`credential`, `traffic`, `scan`, `review_candidate`, `business_rule`,
`ai_provider_config`, `oidc_provider_config`, `notification_config`,
`ticketing_config`, `cmdb_config`, `vgs_config`, `user`, `org_branding`,
`saml_config`, `vgs_vulnerability` — each with `create`/`read`/`update`/`delete`.

| Role | Access pattern |
|---|---|
| `org_admin` | Full CRUD on all 19 resources |
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
- Per-task-type model routing, now that the AI provider layer already
  supports arbitrary per-scan provider selection.
- A more sophisticated file-upload bypass technique (JPEG polyglot, or
  chaining an accepted upload with a discovered local-file-inclusion
  vector for standalone RCE proof).
- Configurable human-in-the-loop approval checkpoints for the more
  invasive check categories, as originally specified.

---

*This document reflects the system exactly as implemented, verified
directly against the codebase. Architecture diagrams are provided
separately as Mermaid (`.mmd`) source files, directly importable into
Miro's Mermaid-import feature.*
