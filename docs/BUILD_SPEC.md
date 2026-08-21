# Build Prompt: Verdikt — AI Multi-Agent Web App & API Security Testing Platform

**Name:** Verdikt
**How to use this document:** Paste this whole file as the initial prompt into Claude Code, Cursor, or any AI coding agent. Work through the Build Roadmap (§13) phase by phase rather than asking for everything at once — each phase is scoped to be buildable and demoable on its own, and validated against the reference vulnerable apps in §14 before moving on. Sections marked **PLACEHOLDER** are intentionally left as pluggable interfaces, not hardcoded implementations.

---

## 0. Role & Objective

You are a senior AI product architect and full-stack engineer. Design and build an enterprise-capable web application that uses a team of AI agents to perform manual-assessment-quality **web application and API security testing** — the kind of testing a skilled human AppSec analyst does with Burp Suite over 3–5 days — and compresses it to **under 1 day**, at a fraction of the cost of running that many analyst-hours or buying multiple commercial scanner licenses.

This is not "just another DAST scanner." The bar is: findings with the same nuance, business-context reasoning, and low false-positive rate a senior analyst would produce, including low/medium-severity issues (headers, cookie flags, info disclosure) and **business logic flaws**, which traditional scanners largely miss.

### Success metrics (design against these explicitly)
- Time-to-report: full assessment of a typical mid-size app/API in <8 hours unattended, <1 day including analyst review.
- Cost per assessment: token/API spend should be a small fraction of one analyst-day's fully loaded cost — enforce this with budget controls, not hope.
- False-positive rate: **zero** in delivered reports. Every finding that reaches a report must be a **confirmed** vulnerability with reproducible evidence, not a heuristic guess. This is a hard gate (see §2, Confirmed-Only Findings Policy), not an aspiration.
- Analyst experience: a security analyst with no coding background should be able to configure and run a full assessment through the UI alone.

---

## 1. Non-Negotiable Guardrails (build these as product features, not afterthoughts)

1. **Authorization gate.** No active-testing agent may run against a target until a project has documented scope (in-scope hosts/paths, explicitly out-of-scope items) and a recorded authorization (uploaded pentest authorization letter / checkbox attestation with named approver). Enforce scope technically — agents get a hard allow-list of hosts/ports, not just a UI reminder.
2. **Safe-by-default intensity.** Default scan profile avoids destructive/DoS-risk payloads (e.g., large-scale brute force, resource-exhaustion tests) unless explicitly enabled per engagement, with a second confirmation.
3. **Full audit trail.** Every HTTP request an agent sends, every LLM call and its cost, every finding's provenance (which agent, which model, which raw evidence) is logged and immutable, tied to the analyst who launched the run.
4. **Human-in-the-loop checkpoints.** Configurable per test category — e.g., require manual approval before running injection payloads against anything flagged as production, or before executing state-changing business-logic tests (payments, account deletion, workflow transitions).
5. **Credential handling.** All target credentials encrypted at rest, never written to logs or LLM prompts in plaintext beyond what's needed for the single request being made, redacted in reports and evidence exports.

---

## 2. High-Level Architecture

```
                     ┌─────────────────────────┐
                     │   Orchestrator Agent      │
                     │ (plans, schedules, fans   │
                     │  out work, tracks budget) │
                     └───────────┬───────────────┘
          ┌───────────┬──────────┼──────────┬─────────────┬────────────┐
          ▼           ▼          ▼          ▼             ▼            ▼
     Recon &      Injection   Auth &     Business      Config/Header   Validation &
     Mapping      Agent(s)    AccessCtrl  Logic Agent   /InfoDisc Agent False-Positive
     Agent                    Agent (priv                              Triage Agent
                              matrix)
          └───────────┴──────────┴──────────┴─────────────┴────────────┘
                                     │
                              Findings Store
                                     │
                            Reporting/Narrative Agent
                                     │
                        HTML / Word / PDF / JSON reports
```

**Design principle:** each agent = deterministic tooling (HTTP client, Burp API calls, header parsers, response diffing) **plus** targeted LLM reasoning calls. The LLM should reason like an analyst over structured evidence (request/response pairs, diffs, response codes, timing) — it should not be freehand-crafting every raw HTTP request from scratch each time; that's slow, expensive, and non-reproducible. Deterministic code executes and records the request; the LLM decides *what to try next* and *what it means*.

**Orchestration engine:** use a durable workflow engine (Temporal.io recommended for enterprise reliability with retries/human-in-loop/long-running jobs; LangGraph is a lighter-weight pure-Python alternative if you want to stay minimal). Parallel fan-out happens across **both** endpoints and vulnerability categories — that's the single biggest lever for cutting wall-clock time from days to hours.

### AI Provider Abstraction — **PLACEHOLDER**

The analyst must be able to configure *any* LLM backend, including a model their own organization has built or self-hosted — this is core to the "cost-effective, not locked to one vendor" requirement.

```python
class AIProviderAdapter(ABC):
    """One adapter per provider. Orchestrator selects provider+model per agent role."""
    @abstractmethod
    async def complete(self, messages: list[Message], model: str,
                        tools: list[ToolSpec] | None, max_tokens: int) -> AgentResponse: ...
    @abstractmethod
    def estimate_cost(self, input_tokens: int, output_tokens: int, model: str) -> Decimal: ...

# Implementations to stub:
#   ClaudeAdapter, OpenAIAdapter, AzureOpenAIAdapter   — named providers
#   CustomEndpointAdapter                              — any OpenAI-compatible HTTP endpoint,
#                                                          covering in-house/self-hosted models
#                                                          served via vLLM, Ollama, LM Studio, TGI,
#                                                          etc. — the analyst just supplies a base
#                                                          URL + API key, no new code per model
```

One clarification worth building in up front: Cursor itself is an IDE, not an LLM API that can be called programmatically, so there's no literal "Cursor adapter" to build. The flexibility that actually matters — plug in whatever model an org has standing behind an API, including a fine-tuned in-house model — is fully covered by `CustomEndpointAdapter` above.

Model selection is per-agent-role and per-project, configurable through a settings screen (§7): the analyst adds a provider, pastes an API key or base URL, hits "test connection," and assigns it to specific agent roles (e.g., a cheap local model for recon, Claude or OpenAI for business-logic reasoning). Never hardcode a single model or provider.

### Confirmed-Only Findings Policy (Zero False Positives)

No candidate a single agent flags may reach a report as-is. Every finding passes a mandatory multi-layer confirmation pipeline before it earns a severity rating and a place in the report:

1. **Deterministic re-execution.** The exact request that triggered the candidate finding is replayed independently (not read from cache/memory) and the triggering condition — error string, boolean/timing differential, status code change, reflected payload, etc. — must reproduce on a fresh request.
2. **Real reproduction for client-side issues.** Anything claiming XSS, clickjacking, DOM-based issues, or CSRF must be proven in an actual headless browser (Playwright) — e.g., JavaScript execution actually observed via a callback/marker, not just a payload string spotted unescaped in a response body. A pattern match alone never confirms a client-side finding on its own.
3. **Adversarial second pass.** A separate Validation Agent, running independently of the agent that found the issue, is explicitly prompted to try to *disprove* the candidate (alternate explanations, environment noise, rate-limiting artifacts, WAF false triggers) before it can be marked Confirmed.
4. **Evidence bundle required.** A finding cannot be marked Confirmed without an attached evidence bundle: raw request, raw response, and — where the vulnerability class is browser-observable — a screenshot (or short sequence of screenshots) proving the effect.
5. **Unconfirmed findings never reach the client-facing report.** Anything that fails steps 1–4 is routed to an internal "Needs Manual Review" queue, visible only to the analyst inside the tool, and never included in exported reports (Word/HTML/PDF/JSON) unless an analyst manually promotes it after their own review — at which point it's flagged in the report as analyst-confirmed rather than AI-confirmed.

This pipeline is what lets the report make a hard claim: **every listed finding is real and reproducible**, so a developer can act on it without first re-validating whether it's noise.

### Tech Stack Fingerprinting & Smart Test Selection ("Smart Scan")

Running every test case in the taxonomy (§3) against every endpoint is the single biggest source of wasted tokens and wasted time — most of it testing things that structurally cannot apply (running PHP-specific LFI payloads against a static SPA with no server-side includes, or SQL-injection variants against an endpoint with no parameter that reaches a database at all). Build this as an explicit early stage, not an afterthought:

1. **Fingerprint before testing.** The Recon & Mapping Agent identifies, per target: web server/CDN, backend language/framework (and version where disclosed), frontend framework, CMS, database hints (error signatures, ORM fingerprints), cloud provider, and third-party JS libraries — using response headers, error pages, static asset paths, cookie naming conventions, and known signature patterns (an open-source signature set such as Wappalyzer's is a reasonable starting point, kept as swappable data, not hardcoded logic).
2. **Filter the test plan, not the findings.** Each row in the coverage taxonomy (§3) carries an `applicable_tech` prerequisite. The orchestrator uses the fingerprint to build a scoped test plan up front — only agents/test-cases whose prerequisites match the detected stack get scheduled — rather than running everything and discarding irrelevant results afterward. This is what actually saves tokens: irrelevant LLM calls are never made in the first place, not filtered out after the fact.
3. **Confidence-aware, not confidence-blind.** Low-confidence or ambiguous fingerprint results should widen the test plan rather than narrow it — err toward testing more, not less, whenever the stack can't be identified with reasonable certainty. Vulnerability classes with no meaningful tech prerequisite (access control, business logic, most header/config checks) always run regardless of fingerprint, since they apply to virtually any stack.
4. **Always offer a manual override.** A "Deep / Paranoid" scan depth (alongside Quick/Standard, §10) disables Smart Scan filtering entirely and runs the full taxonomy — for when the analyst doesn't trust the fingerprint, the target deliberately obscures its stack, or the engagement calls for exhaustive coverage regardless of cost. Surface the detected stack and the resulting test-plan scope to the analyst before the scan starts, with the option to add back any category Smart Scan excluded.

---

## 3. Vulnerability Coverage Model

Build an internal **coverage taxonomy table**, not a hardcoded list — these sources are all updated periodically, and the table should be refreshable:

| Field | Example |
|---|---|
| internal_test_id | `TC-ACCESS-014` |
| owasp_2025_category | `A01 Broken Access Control` |
| cwe_id | `CWE-639` |
| portswigger_topic | `Access control` |
| severity_default | `High` |
| cvss_vector_template | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` |
| applicable_tech | `any` — or a specific list, e.g. `["PHP", "MySQL"]`, consumed by Smart Scan (§2) to decide whether this test case is scheduled for a given target |

**Severity scale:** Critical / High / Medium / Low, derived from the CVSS score computed per finding (Critical 9.0–10.0, High 7.0–8.9, Medium 4.0–6.9, Low 0.1–3.9). A single assessment report must surface **all four levels together** — do not filter Medium/Low out by default. They're routinely the difference between a raw scanner dump and a manual-assessment-quality report; the header/cookie/info-disclosure checks below typically land Medium/Low and are expected deliverables, not noise.

**OWASP Top 10:2025** (current release, replacing 2021) — use as the top-level risk taxonomy:
A01 Broken Access Control · A02 Security Misconfiguration · A03 Software Supply Chain Failures · A04 Cryptographic Failures · A05 Injection · A06 Insecure Design · A07 Authentication Failures · A08 Software or Data Integrity Failures · A09 Security Logging and Alerting Failures · A10 Mishandling of Exceptional Conditions.

**CWE Top 25 (2025, CISA/MITRE — annually refreshed)** — map every test case to a CWE ID; top of the current list is XSS (CWE-79), SQL Injection (CWE-89), and CSRF (CWE-352), with newer entrants like Improper Access Control (CWE-284) and buffer overflow variants.

**PortSwigger Web Security Academy** — use this as the master test-case *catalog spine*, since it's the most exhaustive open taxonomy of concrete techniques (not just categories) including business logic. Build one or more test cases per topic:
SQL injection · XSS · CSRF · Clickjacking · CORS · XXE · SSRF · HTTP request smuggling · Command injection · Server-side template injection (SSTI) · Insecure deserialization · Path/directory traversal · Access control · Authentication · OAuth · Business logic vulnerabilities · WebSockets · DOM-based vulnerabilities · Web cache poisoning · Web cache deception · HTTP Host header attacks · Information disclosure · File upload vulnerabilities · JWT attacks · Prototype pollution · GraphQL API vulnerabilities · Race conditions · NoSQL injection · API testing · Web LLM attacks.

**Explicit low/medium checks** (often skipped by scanners, expected in a manual report):
- Security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- Cookie flags: `Secure`, `HttpOnly`, `SameSite`
- TLS/cipher configuration and protocol version support
- Verbose errors / stack traces / debug endpoints left enabled
- Directory listing, backup/config file exposure, version disclosure (`Server`, `X-Powered-By`)
- Cache-Control on authenticated/sensitive responses
- Autocomplete enabled on sensitive form fields
- `robots.txt` / sitemap / `.well-known` information leakage
- CORS misconfiguration (wildcard + credentials, reflected origin)

**Business logic testing** — this can't be fully generic. During project setup, walk the analyst through a short **business-rules questionnaire** ("what should never be possible here?" — e.g., "a user should never see another user's order," "discount codes should not stack," "an order can't ship before payment clears"). The Business Logic Agent uses these as explicit assertions to test against, layered on top of generic checks (workflow-step bypass, mass assignment, IDOR chains, quantity/price tampering, race conditions on limited-use resources, multi-step transaction tampering).

---

## 4. Traffic & Target Ingestion — **PLACEHOLDER: `TrafficImporter` interface**

All ingestion paths normalize into one canonical schema so every downstream agent is source-agnostic:

```python
class HttpInteraction(BaseModel):
    request: HttpRequest       # method, url, headers, body, query params
    response: HttpResponse     # status, headers, body, timing_ms
    source: Literal["manual","burp_live","har","burp_file","zst_traffic","webinspect_macro"]
    credential_set_id: str | None
    timestamp: datetime

class TrafficImporter(ABC):
    @abstractmethod
    def parse(self, file_path: str) -> list[HttpInteraction]: ...

# Implementations: HarImporter, BurpFileImporter, CheckmarxZstImporter, WebInspectMacroImporter
```

Supported ingestion methods:
1. **Manual target entry** — single URL or list, with optional crawl/spider step.
2. **Burp sitemap selection** — analyst picks a node or branch of an already-mapped Burp site map and triggers a scan against just that subtree.
3. **File upload** — `.har`, `.burp` (Burp project/state file), `.zst` (Checkmarx traffic archive), WebInspect macro/workflow files. Build these importers as adapters; you don't need sample files to start — build against the documented/open format specs (HAR is a public JSON spec; Burp's format and Checkmarx `.zst` may need reverse-engineering a sample export once available — flag this as a Phase 4 item, not a blocker for MVP).
4. **Direct Burp Suite integration** — Burp REST API (Enterprise/Pro) for triggering/reading scans, plus a custom Burp extension (Montoya API, Java/Kotlin) that adds a "Send to Verdikt" context-menu item, mirroring how analysts already send requests to Repeater/Intruder.
5. **Login macro recorder** — a Playwright-backed in-browser recorder: analyst performs a real login once, the tool captures the action sequence (navigations, field fills, clicks, wait conditions, optional manual-OTP pause) as a reusable macro tied to a credential set. Every agent that needs a fresh session replays the macro automatically instead of failing on session expiry mid-scan.

---

## 5. Credentials & Privilege Matrix

- Support 2–4 credential sets per project (e.g., Admin, User A, User B, Guest/unauthenticated).
- Auto-generate the test matrix from discovered endpoints:
  - **Horizontal:** User A's session attempting to access/act on User B's resources.
  - **Vertical:** lower-privilege session attempting admin-only endpoints/actions.
- Credential vault: envelope-encrypted at rest (KMS adapter — **PLACEHOLDER**), scoped per project, redacted everywhere in UI/reports except a masked reference.

---

## 6. Data Model & Persistence — **PLACEHOLDER: `DatabaseAdapter`**

Core entity hierarchy: `Organization → Project → Version/Engagement → Target(s) → CredentialSet(s) → ScanRun → AgentJob → Finding → Evidence → Report`.

```python
class DatabaseAdapter(ABC):
    """Default implementation: PostgreSQL via SQLAlchemy + Alembic.
    Must also support MySQL / SQL Server / Oracle / SQLite by swapping the dialect —
    keep all queries ORM-level, no raw-SQL dialect-specific features in core paths."""
    @abstractmethod
    def get_session(self) -> Session: ...
```

Also abstract **object storage** for raw evidence/traffic/report files: local disk by default, S3/Azure Blob as swappable adapters — same interface pattern as above.

Every scan run belongs to a **Version**, so re-scanning after fixes produces a comparable history and supports regression/diff reporting (§8).

### Rescan & Retest — two different operations, both first-class

- **Rescan** = re-run the full test plan for a project/version from scratch (new `ScanRun`, same Version or a new one). Use this for a scheduled re-assessment or after enough changes that a full pass makes sense.
- **Retest** = re-verify one specific `Finding` (or a selected batch) without re-running the whole assessment. This is what an analyst uses the day after a dev pushes a fix: it replays that finding's exact `steps_to_reproduce`, re-runs it through the Confirmed-Only Findings Policy (§2), captures fresh evidence (including a new screenshot, §8), and updates `retest_status` — `fixed` if it no longer reproduces, or reopened with a note if it still does.

```python
class RetestJob(BaseModel):
    id: str
    finding_ids: list[str]        # one or more findings being retested together
    triggered_by: str             # analyst identity
    scan_run_id: str | None       # if run as part of a broader rescan, otherwise None
    result: dict[str, Literal["fixed", "still_present", "inconclusive"]]  # per finding_id
    evidence: dict[str, FindingEvidence]   # fresh evidence per finding_id, see §8
    completed_at: datetime
```

Every finding's report entry should show its retest history (date, result, who/what triggered it), not just its current status — this is what makes the diff report (§8) and a client's "prove it's fixed" ask trivial instead of a re-run of the whole engagement.

---

## 7. UI/UX

- **Dashboard:** open findings by severity/category over time, mean time-to-assess, cost-per-scan, active scans, org-wide risk heat-map.
- **LLM/Provider settings:** add a provider (Claude, OpenAI, Azure OpenAI, or a custom OpenAI-compatible endpoint for an in-house/self-hosted model), paste an API key or base URL, test the connection, then assign providers/models per agent role and per project — this is the configuration surface for §2's `AIProviderAdapter`.
- **Project/version setup wizard:** targets → scope/authorization attestation → credential sets → business-rules questionnaire → traffic import or Burp connection → AI provider + depth ("Quick / Standard / Deep / Deep-Paranoid") → schedule or run now.
- **Detected tech stack panel:** shown before a scan starts, listing what Smart Scan (§2) fingerprinted and which test categories it will run or skip as a result, with a control to add back any excluded category or force full-taxonomy coverage.
- **Live scan monitor:** per-agent progress, live findings feed, running cost/token meter, pause/kill controls.
- **Findings triage board:** kanban (New → Confirmed → False Positive → Fixed → Risk Accepted), analyst can edit the AI-written narrative, adjust severity/CVSS, attach extra evidence, and trigger a **Retest** on one or more selected findings.
- **Rescan control:** on the project/version page, trigger a full re-run independent of any single finding's retest — surfaced separately from Retest so the two operations (§6) aren't conflated in the UI.
- **Report builder:** choose sections, format, add company letterhead/branding.

---

## 8. Reporting — multi-format, analyst-editable, understandable by anyone

Formats: interactive **HTML** (self-contained dashboard-style report), **Word** (`.docx` via a template with company letterhead — use python-docx patterns), **PDF** (Jinja2 → WeasyPrint), and **CSV/JSON** (for ticketing/SIEM ingestion).

### Per-finding requirements (non-negotiable — this is what makes it "manual-assessment quality")

Every finding in every report format must carry **all** of the following fields. A finding is not report-ready if any are missing:

```python
class Finding(BaseModel):
    id: str
    title: str
    severity: Literal["Critical", "High", "Medium", "Low"]
    owasp_2025_category: str
    cwe_id: str
    portswigger_reference_url: str | None
    cvss_vector: str
    cvss_score: float
    affected_endpoints: list[str]

    plain_language_summary: str      # 2-4 sentences, no jargon — "what this means and why it
                                      # matters," written so a PM, developer, or executive with
                                      # zero security background understands the risk immediately
    technical_description: str       # full technical detail for the analyst/dev audience

    evidence: FindingEvidence        # see below
    steps_to_reproduce: list[str]    # numbered, tool-agnostic instructions a developer can
                                      # follow independently to get the same result
    remediation: str                 # specific and actionable, ideally tailored to the detected
                                      # framework/language rather than generic advice
    references: list[str]            # CWE page, OWASP 2025 category page, PortSwigger
                                      # lab/topic link, relevant vendor advisory if applicable

    confirmation_status: Literal["ai_confirmed", "analyst_confirmed"]
    retest_status: Literal["open", "fixed", "risk_accepted", "false_positive_after_review"]
    retest_history: list[RetestJob]  # every retest run against this finding (§6), each with its
                                      # own fresh evidence — the report shows this, not just the
                                      # latest status, so "prove it's fixed" is answerable at a glance

class FindingEvidence(BaseModel):
    request_raw: str
    response_raw: str
    screenshots: list[ScreenshotRef]   # see Evidence Capture below — REQUIRED, not optional,
                                        # for every finding that can be reproduced in a browser
    additional_notes: str | None
```

### Evidence capture — screenshots and dev-reproducible steps

Screenshots are a **required** part of the evidence bundle, not a nice-to-have — build a dedicated **Evidence Capture** subsystem (Playwright-based) that runs automatically once a finding is Confirmed, and again on every Retest (§6):
- Replays the `steps_to_reproduce` sequence in a real headless browser.
- Captures a screenshot at each meaningful step — e.g., before payload submission, the vulnerable state/response rendered, and, for client-side issues, the actual exploited effect (an executed script, a redirected/altered page, an unauthorized record displayed).
- For API-only findings with nothing to render, capture an annotated, syntax-highlighted request/response pair instead of a screenshot, so the evidence bundle is always visual and self-explanatory without hunting for a separate attachment.
- Store all evidence linked to the finding ID so it renders inline in HTML/Word/PDF reports.

`steps_to_reproduce` must be written so a developer with no access to this tool and no security background can follow them manually against the same environment and get the same result — e.g., *"1. Log in as User A. 2. Navigate to /account/invoices/1042. 3. Change the URL to /account/invoices/1043 (an invoice belonging to a different account). 4. Observe that the invoice loads instead of returning a 403."* — never *"the agent detected an IDOR via automated ID enumeration."*

### Report structure — written for two audiences at once

Every report, not just the executive summary, needs to work for a reader with zero security background:
- Open with a **"How to read this report"** page: severity levels explained in plain business terms (not just the CVSS math), plus a short glossary of any technical term used later (IDOR, XSS, CSRF, etc.).
- Every finding leads with `plain_language_summary` before the technical detail, so the non-technical reader never has to parse a CVSS vector to understand impact.
- Business impact is framed in business terms first (*"an attacker could view other customers' invoices without authorization"*) with the technical mechanism explained immediately after, not instead of.

### Report views generated from one dataset

- **Executive summary:** risk heat-map, top findings, trend vs. last version — no jargon, decision-oriented.
- **Full technical report:** every Confirmed finding with the complete field set above — screenshots, request/response, steps to reproduce, remediation, references.
- **Diff report:** against the prior scan of the same project (new / fixed / recurring findings) — makes re-testing after a dev fix take minutes instead of a full re-run.

All severities — **Critical, High, Medium, and Low** — appear together in the technical report by default; never silently filter to High/Critical only. Medium/Low findings (headers, cookie flags, info disclosure, etc.) are expected deliverables of a manual-quality assessment, not noise to hide.

---

## 9. Enterprise Extensibility — **PLACEHOLDER adapters**

Stub these as interfaces from day one even if only one implementation ships early:

```python
class IdentityProviderAdapter(ABC):      # Okta / Azure AD / generic SAML or OIDC
    async def authenticate(self, token: str) -> UserIdentity: ...

class CMDBAdapter(ABC):                  # pulls asset inventory + owner/criticality
    async def get_asset(self, identifier: str) -> AssetMetadata: ...

class TicketingAdapter(ABC):             # Jira / ServiceNow
    async def create_ticket(self, finding: Finding) -> TicketRef: ...
    async def sync_status(self, ticket_ref: TicketRef) -> TicketStatus: ...

class NotificationAdapter(ABC):          # Slack / Teams / email
    async def notify(self, event: ScanEvent) -> None: ...
```

**RBAC roles** (baseline): Org Admin, Project Lead, Analyst, Client/Read-Only Viewer. Model as a permission matrix table, not hardcoded role checks, so new roles are configuration, not code.

---

## 10. Cost & Time Strategy (why multi-agent + this design actually hits the 1-day target)

1. **Smart Scan — tech-stack-aware test selection (§2).** Fingerprinting the target and scoping the test plan to what's actually applicable before running anything is likely the single biggest token-savings lever available: irrelevant categories are never scheduled, not filtered out after an expensive LLM call. A "Deep/Paranoid" override remains available when the analyst wants full-taxonomy coverage regardless of cost.
2. **Model routing by task, not one model for everything.** Cheap/fast models handle recon, header/config checks, and pattern-matching (most of the request volume). Reserve frontier-tier models for business-logic reasoning, multi-step exploit chains, and final report narrative — this is where cost is disproportionately saved.
3. **Parallel fan-out across endpoints, not just categories** — the main lever for wall-clock time.
4. **Deterministic pre-filtering before any LLM call** — tech fingerprinting, known-version CVE matching, and header presence/absence are pure code, zero tokens. Only ambiguous cases get escalated to an LLM call.
5. **Caching/dedup** — identical endpoint+parameter combinations are tested once and results reused across credential sets where behaviorally valid, instead of re-run per credential.
6. **Visible budget guardrails** — per-scan token/cost cap, a live cost meter in the UI, and a "depth" slider (Quick/Standard/Deep/Deep-Paranoid) that maps to a concrete agent/model configuration profile, so the analyst — not a runaway loop — controls spend.

---

## 11. Integrating with VGS (your existing open-source DAST governance tool)

Two viable paths, in order of recommendation:

1. **Decoupled (recommended to start):** build this as its own service/repo. VGS stays the governance/tracking system of record (it already ingests DAST findings and tracks remediation lifecycle); this platform becomes the AI assessment *engine*, pushing structured findings (JSON, tagged `source: ai-multi-agent`) to VGS via its existing ingestion API/webhook. Lower coupling, easier to iterate fast, and it also stands on its own as a second, independently demonstrable open-source project — useful both as a portfolio artifact and for the adoption-metrics evidence you're building toward EB-1A.
2. **Integrated:** expose this as a plugin/microservice inside VGS's existing FastAPI backend, sharing its Postgres instance and auth layer. Less duplication, but tighter coupling makes independent scaling and independent open-source attribution harder later.

Start with (1); revisit (2) once the core agent pipeline is proven.

---

## 12. Suggested Tech Stack

- **Backend:** Python + FastAPI, Pydantic schemas (consistent with VGS and your AI-assisted build workflow)
- **Orchestration:** Temporal.io (durable, retryable, supports human-in-loop) or LangGraph (lighter-weight)
- **Task queue (if not using Temporal):** Celery + Redis
- **DB:** PostgreSQL default via SQLAlchemy + Alembic, behind the `DatabaseAdapter` interface
- **Frontend:** React + TypeScript + Tailwind (shadcn/ui components) — consistent with VGS's frontend
- **Browser automation:** Playwright (macro recorder + any agent-driven UI interaction)
- **Tech-stack fingerprinting:** an open-source signature set such as Wappalyzer's (kept as swappable/updatable data, not hardcoded logic) to drive Smart Scan (§2)
- **Burp integration:** Burp REST API + custom Montoya API extension
- **Reporting:** python-docx (Word), Jinja2 + WeasyPrint (HTML/PDF)
- **Deployment:** Docker Compose for self-host, Helm chart for k8s/enterprise — same distribution pattern as your existing Docker Hub image for VGS

---

## 13. Build Roadmap

| Phase | Scope |
|---|---|
| 0 — Foundations | Data model, `DatabaseAdapter`, auth/RBAC skeleton, project/version CRUD, credential vault, canonical `HttpInteraction` schema, HAR importer |
| 1 — Single-agent MVP | Recon agent + tech-stack fingerprinting (initial signature-based) + Header/Config/InfoDisclosure agent (cheapest, highest immediate ROI, mostly deterministic) + basic HTML/JSON report |
| 2 — Multi-agent core | Injection, XSS, Auth, Access-Control agents; orchestrator with parallel fan-out; credential/privilege matrix engine; AI provider abstraction (Claude + OpenAI adapters, generic `CustomEndpointAdapter` for in-house/self-hosted models); Smart Scan test-plan filtering from fingerprint (§2); Confirmed-Only Findings pipeline (deterministic re-execution + adversarial validation pass, §2) |
| 3 — Business logic | Business-rules questionnaire UI, Business Logic agent, workflow/race-condition/mass-assignment checks |
| 4 — Traffic integrations | Live Burp integration, login macro recorder, `.burp`/`.zst`/WebInspect importers |
| 5 — Reporting suite | Word/PDF/HTML/executive-summary/diff reports, dashboard analytics, Evidence Capture subsystem (Playwright screenshots), dual-audience finding narratives, Rescan (full re-run) and Retest (targeted per-finding re-verification) workflows (§6) |
| 6 — Enterprise hardening | Okta/SSO, CMDB, ticketing, cost governor polish, VGS integration, multi-tenant RBAC |

**Do not advance to the next phase without the validation pass in §14** — run the reference-app scan-and-reconcile against OWASP Juice Shop (and AltoroMutual once workflow/business-logic phases are underway), confirm nothing is missed and nothing false-positives, and only then move on.

---

## 14. Testing & Validation Strategy During Development

Use known deliberately-vulnerable applications as ground truth throughout the build. This is what proves each phase actually works before moving to the next — not just that it runs without errors, but that it finds what a human analyst would find, and nothing else.

### Reference targets
- **OWASP Juice Shop** — the primary validation target. It's actively maintained, covers a large slice of OWASP Top 10:2025 and the PortSwigger topic list (injection, broken access control, XSS, business logic flaws, insecure deserialization, etc.), and ships with a public list of 100+ documented challenges with known solutions — a real answer key to grade the tool against. Self-host it (official Docker image) rather than scanning any public instance, so you get a clean, reproducible baseline and unambiguous authorization.
- **demo.testfire.net (IBM AltoroMutual)** — a long-standing, publicly authorized deliberately-vulnerable banking demo app. Useful as a second, differently-structured target (classic server-rendered banking workflows vs. Juice Shop's modern SPA/API style), which is good for exercising business-logic and multi-step workflow checks against something structurally different from the app every other AI pentest tool benchmarks against.
- Add over time: **DVWA** and **OWASP WebGoat**, both good for isolating individual vulnerability classes — DVWA in particular lets you dial difficulty up per vuln, useful for checking whether agents still catch an issue once basic filtering/obfuscation is layered on.

### How to use them, per phase
1. **Know the answer key before writing the agent.** Juice Shop's published challenge list and documented write-ups for AltoroMutual/DVWA/WebGoat tell you exactly what should be found, at what severity, in which category. Don't discover coverage gaps by accident — test against targets where the correct finding set is already known.
2. **After every phase, run a full scan against both reference apps and manually reconcile the results:**
   - **Recall check** — every known vulnerability in the answer key that *should* have been found: was it?
   - **Precision check** — everything the tool *did* report: is it real, per the Confirmed-Only Findings Policy (§2), with a valid evidence bundle, or did something slip through unconfirmed?
   - **Accuracy check** — do severity, OWASP 2025 category, and CWE mapping look right, not just "a finding fired"?
3. **Treat this as integration testing, not just unit testing.** The point isn't only "does the SQLi agent fire on a known-SQLi endpoint" — it's whether every phase is stitched together correctly end to end: orchestrator → recon → credential/privilege matrix → category agents → validation agent → reporting agent, with no findings lost, duplicated, or mis-attributed at the handoffs. Re-run the full pipeline against Juice Shop after any phase that touches the orchestrator or data model, not only after reporting-related phases.
4. **A phase is not "done" until this manual reconciliation passes.** Move to the next phase only once: (a) the known vulnerabilities in the reference apps are found and Confirmed, (b) nothing is reported that isn't real, and (c) a manually-reviewed sample of evidence bundles (request/response, screenshots, steps to reproduce) actually holds up when followed by hand.
5. **Keep a running scorecard** per reference app — known vulnerability → found/not found → confirmed/false-positive → phase first validated in. This doubles as your regression suite (re-run it after any agent-prompt change) and gives you a concrete, defensible metric later, e.g. "correctly identified and confirmed 47 of 51 known Juice Shop vulnerabilities with zero false positives."

### Guardrail
Self-host these reference apps in an isolated environment (Docker, no public exposure). Never point the tool's agents at anyone else's public instance of them, and never treat this reference-app testing as a substitute for the real authorization/scope checks (§1) once the tool is pointed at an actual client application.

---

## 15. Instructions to the Building AI Agent

Before writing code for any phase: confirm which phase you're building, then produce, in order: (1) repo scaffold, (2) data models, (3) API contracts, (4) agent prompts as versioned config files (YAML/JSON per test category — never hardcode prompt text inline in application code, since these need to be tunable without redeploying), (5) tests. Ask a clarifying question only where this brief is genuinely ambiguous for the phase at hand — otherwise proceed with the defaults stated above and note the assumption in your output.
