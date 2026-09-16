# Verdikt — Frequently Asked Questions

Answers here are grounded directly in the current code (file references
included) — nothing here is aspirational or roadmap. If a claim below ever
stops matching the code, the code wins; open an issue.

---

## 1. How does the crawl/spider work?

`ReconAgent` (`app/agents/recon.py`) does a bounded, same-origin, breadth-first
crawl starting from each in-scope `Target`'s base URL, `/robots.txt`, and
`/sitemap.xml`:

- **Bounded by design, not by accident.** Default caps are 300 pages / depth 6
  (`Settings.crawl_max_pages` / `crawl_max_depth`, overridable per deployment)
  — large enough for a real application, never truly unbounded even against a
  fully authorized target. Concurrency is capped at 5 in-flight requests so
  the crawl doesn't hammer the target.
- **Every request is scope-checked.** `ScopedHttpClient` enforces the
  `Version`'s allow-list (`ScopeEntry` rows) on every single request the
  crawl (or any other agent) makes — not a UI reminder, a hard technical
  control.
- **It runs twice.** Once unauthenticated (`recon` node), and again as a
  logged-in user once a credential's login succeeds (`authenticated_recon`
  node). This matters a lot: a purely pre-login crawl was found live (against
  a real target) to discover exactly one form — the login page's own —
  because almost an entire real application's surface sits behind
  authentication. The authenticated pass re-crawls from everything already
  discovered, now with a session, and finds the rest.
- **It follows redirects as first-class frontier entries** (not silently, and
  not auto-followed at the HTTP layer — `ScopedHttpClient` never auto-follows
  redirects, so every hop stays individually scope-checked), and it skips
  Logout links on purpose — a crawl that clicks "Logout" mid-scan kills the
  shared session every other concurrent agent is relying on. It still
  captures each one separately (`discovered_logout_urls`), so the dedicated
  `session_invalidation` check has a real logout URL to test against via its
  own disposable login, never the shared session.
- **It extracts, as it goes:** every `<form>` (action, method, fields), every
  query-string parameter on every URL it fetches, and any literal
  `wss?://` string in a page or script body (WebSocket endpoints, which
  never show up any other way since a static-HTML crawl can't execute JS).
  These feed directly into the injection/XSS/CSRF/file-upload/WebSocket
  agents as their actual testing surface.
- **An AI pass (`recon_planner`) runs once, after both crawls,** reviewing the
  site map to suggest additional plausible-but-unlinked paths (e.g. an
  `/api/v1/users` guessed from a discovered `/api/v1/products`). Every
  suggestion is a *hypothesis*, never a claim — each one is verified with a
  real, live request before it's added to anything; a guess that doesn't
  actually resolve is discarded, not reported.
- **Imported traffic (HAR/Burp/Postman/Zest/OpenAPI, or a manually pasted
  request) is fed in as crawl seeds, not just unioned onto the result
  afterward** — see question 4 below for the full story on how uploaded
  traffic and live crawling combine.

## 2. How is the audit done? How are vulnerabilities identified? What's AI's role? Are the payloads any good?

Every detection agent (injection, XSS, access control, business logic, SSRF,
and the rest) runs the same four-stage pipeline — no agent, including
AI-heavy ones, skips a stage:

1. **Deterministic probe.** A real HTTP request carrying a real payload is
   sent, and the response is compared against a baseline using a
   **hard-coded, non-AI signal**: an error string appears in the probe
   response but not the baseline (SQLi error-based); response length/content
   differs meaningfully between a true-condition and false-condition payload
   (SQLi boolean-blind, NoSQLi); a unique marker echoes back in a command's
   output (OS command injection); `{{7*7}}` evaluates to `49` (SSTI); `/etc/passwd`
   content appears (path traversal). **Nothing becomes a candidate without
   one of these signals firing first** — AI is never the thing that notices
   something might be wrong.
2. **LLM triage.** Only a candidate that already tripped a deterministic
   signal gets shown to the model, along with that signal and both raw
   HTTP exchanges, and asked for a strict verdict:
   `{"vulnerable": bool, "confidence": ..., "reasoning": ...}`. Model output
   that doesn't parse as that exact schema — a chatty non-JSON reply, a
   missing field — is treated as "couldn't confirm," never guessed into a
   finding (`app/ai/verdict.py::parse_verdict`).
3. **Deterministic re-execution.** If triage says "vulnerable," the exact
   same probe is sent again, fresh, right now. If it doesn't reproduce, the
   candidate is discarded silently — a flaky one-time response never becomes
   a finding.
4. **Adversarial LLM validation.** A *second*, independent model call is
   given the reproduced result and explicitly asked to try to disprove it.
   Only if it can't does the finding get persisted, with that adversarial
   reasoning stored right on the finding record as part of its evidence.

**Reflected XSS gets one extra, stronger step:** after surviving all four
stages above, a real headless browser actually loads the page and checks
whether the injected script *executes* — not just whether it appears in the
HTML — before a screenshot is captured as evidence and it's persisted as
Confirmed (`app/agents/xss_browser_proof.py`). A candidate that survives
triage but the browser doesn't confirm (e.g. blocked by CSP) becomes a
**Review Candidate** instead of a Finding — visible in the UI for a human
to look at, clearly distinguished from something Verdikt is asserting as
true. This Confirmed-vs-Review-Candidate split is deliberate: a scanner that
only ever emits one flat list of "potential" findings makes every one of
them the analyst's problem to triage; here, only what survived the full
gate gets called Confirmed.

**Where AI actually adds value, concretely:**

- **Judgment on ambiguous signals** (stage 2/4 above) — a differential
  response or a benign-looking error string isn't self-interpreting; the
  model reasons about whether it's actually consistent with the claimed
  vulnerability class, in context, for *this* specific response.
- **Context-aware payload generation.** Beyond a fixed payload battery
  (the bare `'`, `verdikt1' OR '1'='1`, etc.), one extra AI call per scan
  (not per-parameter — that would burn the whole scan's LLM budget on the
  first few parameters) generates a small batch of additional payloads
  informed by the actual discovered parameter names and the detected tech
  stack (`app/agents/injection.py::_generate_ai_payloads`). A concrete example
  already validated live: a parameter that only broke on a **numeric-context**
  payload with no quote at all (`1 OR 1=1--`) — the fixed battery's `'` never
  found it; an AI-suggested, tech-stack-aware payload did. Critically: **a bad
  AI-suggested payload just doesn't trip the same deterministic signal
  everything else is judged by** — there's no separate trust path for
  AI-sourced payloads, so a wrong suggestion can't cause a false finding, only
  a missed one (same as a fixed payload that doesn't happen to work against a
  particular target).
- **Hypothesis generation for things that can't be pattern-matched at all** —
  business logic and IDOR. `BusinessLogicPlannerAgent`
  (`app/agents/business_logic_planner.py`) reviews the site map and proposes
  test hypotheses (e.g. "this looks like a per-user resource endpoint —
  check whether one identity can access another's"). Its own docstring
  states the invariant plainly: *"the LLM here proposes what to test and
  how, never whether something IS vulnerable"* — every proposal becomes an
  ordinary `BusinessRule` row that flows through the identical
  deterministic-detector → triage → validation gate as a rule an analyst
  typed in by hand. A malformed proposal is discarded outright, never
  best-effort-repaired.
- **Narrating compound attack chains** *after* everything else is done.
  `ChainAnalysisAgent` (`app/agents/chain_analysis.py`) reviews the full set
  of already-Confirmed findings together and proposes multi-step exploit
  narratives connecting them (e.g. "the SQLi in step A can extract the
  session token used to bypass the access control gap in step B"). Same
  two-pass triage-then-adversarial-validation discipline applied to the
  chain as a whole — it never proposes a chain using a finding that wasn't
  already independently confirmed.

**Guardrails that keep AI's role honest in practice:**

- A per-scan-run **LLM cost cap** (`Settings.max_llm_cost_usd_per_scan`,
  visible on every scan run) hard-stops further AI-dependent checks once
  hit — the agent returns what it already confirmed rather than either
  silently truncating or running away unbounded.
- `AI_PROVIDER` defaults to `fake` — a no-op adapter that returns nothing
  vulnerable. A fresh, unconfigured install runs the full pipeline end to
  end and finds real header/config/plaintext issues (the fully
  deterministic checks need no AI at all) but zero AI-triaged findings,
  by design — so there's never an ambiguous state where the tool might be
  silently hallucinating in production without a model actually wired up.

## 3. How is this different from WebInspect, Checkmarx, etc. — why use this instead?

Worth separating the comparison, since they're different categories of tool:

**Checkmarx is SAST** (static analysis of source code, no running
application involved) — it finds a different class of issue (e.g. a
dangerous sink reachable in code that may never actually be exercised at
runtime) and needs source access in a supported language. Verdikt is
dynamic (DAST) — it only knows what it can observe by actually talking to a
running application, language- and framework-agnostic by construction. These
aren't competitors so much as complementary — a mature program runs both.

**WebInspect is the closer comparison** (also DAST). The honest
differences, grounded in what's actually built here:

- **Confirmed-only-by-default output, not a flat "potential findings" dump.**
  Traditional DAST scanners are well known for a firehose of results an
  analyst has to triage from scratch, because most detection is pure
  pattern-matching with no second-pass judgment. Verdikt's four-stage
  pipeline (question 2) means a Finding already survived deterministic
  re-execution *and* an adversarial pass explicitly trying to disprove it —
  the "is this real" work happens before the report, not after. What
  doesn't fully clear that bar (e.g. an XSS candidate a browser couldn't
  confirm actually executes) still surfaces, but explicitly labeled as a
  Review Candidate, not mixed in as if it were equally certain.
- **Business logic and IDOR are a first-class target, not an afterthought.**
  These are exactly the vulnerability classes a signature/pattern-matching
  scanner structurally can't find, because there's no fixed pattern for "this
  specific app's specific workflow can be done out of order" or "this
  specific resource ID scheme leaks another user's data." Verdikt's AI
  hypothesis-generation (question 2) exists specifically to widen coverage
  here, still gated by the same deterministic-confirm-then-validate pipeline
  as everything else — and a full identity/credential matrix
  (`app/agents/matrix.py`) tests horizontal *and* vertical privilege
  escalation across every configured credential, including
  privilege-ranked role-vs-role comparisons.
- **Attack-chain narratives, not just a deduplicated finding list.** Most
  scanners report N independent findings and leave connecting them into a
  real exploit story to the human reader. `ChainAnalysisAgent` does that
  synthesis automatically once a scan finishes.
- **A real login is recorded once, replayed everywhere.** The in-app
  VNC-streamed recorder (or the standalone browser extension for a
  native/no-Docker setup) captures a real login flow as a replayable macro —
  including a manual OTP/SSO step, paused and resumed — used by every agent
  that needs a fresh session, instead of a scan silently going unauthenticated
  the moment a session expires mid-run (a real, previously-live bug this
  exact design fixes).
- **Built for a specific downstream workflow, not just a report file.**
  Native Jira/Slack/Teams ticketing and notifications, a CMDB asset-owner
  lookup, SSO (SAML/OIDC), and — distinctively — a native VGS
  report-builder workspace that can also auto-seed a scan's confirmed
  findings directly into a report draft.
- **Self-hosted and source-available**, so "point it at an internal LLM
  gateway" (any OpenAI-chat-completions-compatible endpoint) or "add a new
  check" is a real option, not a vendor feature request.

**Said plainly, the honest tradeoff:** Verdikt is younger than a 20-year-old
commercial scanner, and every AI-triaged check costs real time and (a
capped amount of) real money per scan — a fully deterministic scanner with
no LLM calls will always be faster and cheaper per request. The bet this
tool makes is that the reduction in false-positive triage work and the
coverage of logic-level vulnerabilities a pattern-matcher structurally can't
reach are worth that cost.

## 4. If I upload a traffic file, does the tool only test that traffic, or does it also crawl the live site?

**Both, combined into one crawl — not two separate things.** Imported
traffic (HAR, Burp export, Postman collection, Zest script, OpenAPI/Swagger
spec, or a single request pasted in manually) is read *before* the crawl
starts and fed in as additional starting points for `ReconAgent`
(`app/agents/graph.py::recon_node`, via `app/agents/traffic_seed.py`) —
exactly like the target's own homepage/robots.txt/sitemap.xml are.

Concretely, that means:

- Every endpoint your traffic file captured gets tested directly, with **no
  crawling required to rediscover it** — this is what makes a client-rendered
  SPA's real API surface testable at all, since its calls never appear as
  literal URLs in any HTML the crawler could otherwise find.
- The crawler then **also follows links reachable from those imported
  URLs**, not just the URLs themselves — a page only linked from an
  imported API response, never from the site's own static HTML, still gets
  discovered and tested.
- The live target is crawled independently in parallel regardless of
  whether you imported anything — traffic import *adds* coverage, it never
  narrows or replaces the normal crawl.
- An OpenAPI/Swagger spec is expanded into one interaction per declared
  operation (`app/importers/openapi_importer.py`) — including its declared
  query parameters, which get fuzzed exactly like a parameter found by
  crawling.

So: uploading traffic never means "only these requests get tested" — it
means "these requests are guaranteed to be tested, on top of whatever the
live crawl finds on its own."

## 5. What's the architecture, and what's AI's role given deterministic scanning is already in place?

**Orchestration:** one scan run compiles and executes a 31-node
[LangGraph](https://github.com/langchain-ai/langgraph) DAG
(`app/agents/graph.py::build_graph`) — real parallel fan-out, not a
sequential loop. Recon fans out to every check that only needs a site map
(header/CORS/clickjacking/XXE/GraphQL/deserialization/SSRF/prototype-
pollution/etc.) in parallel; once login establishes sessions,
`authenticated_recon` re-crawls, then `recon_planner` runs once as a gate
before the big post-login fan-out (injection/XSS/auth/access-control/
business-logic/CSRF/stored-XSS/file-upload/WebSocket/weak-password-policy/
CSV-injection/session-invalidation/vulnerable-components) — again all in
parallel. `ChainAnalysisAgent` runs once more afterward, outside the graph
proper, over the complete set of that run's Confirmed findings.

**Why AI has a real role even though every check starts from a
deterministic signal:** because a deterministic signal is *evidence*, not a
*verdict*. "An error string differs between two responses" or "a workflow
step succeeded without its prerequisite" is a fact about HTTP traffic — it
doesn't yet say whether that fact means anything, in context, for this
specific application. Two design choices carry that judgment work, and both
are the reason this isn't "AI scanning" in the sense of "ask a model if a
site is vulnerable":

1. **AI never originates a finding from nothing.** Every single AI call in
   the whole pipeline — triage, adversarial validation, payload suggestion,
   business-logic hypothesis, chain narrative — takes a real, already-
   gathered deterministic artifact as its starting input. There is no code
   path where a model is asked "is this app vulnerable?" in the abstract.
2. **AI's output is itself gated by more determinism, not trusted
   outright.** A "vulnerable" triage verdict still has to survive a fresh,
   real re-execution of the same probe before anything else happens to it.
   An AI-proposed business-logic hypothesis is just a new row in the same
   table an analyst's own hand-typed rule lives in, tested by the exact
   same code. An AI-suggested payload either trips the same deterministic
   signal as a hand-picked one, or it's silently discarded — never a
   separate, lower-bar path to a finding.

In short: the deterministic layer decides *what's even worth asking about*
and *whether a claimed positive actually reproduces*; the AI layer decides
*whether the specific evidence gathered actually supports the specific
claim being made*, and *what's worth testing at all* in the categories
(business logic, plausible-but-unlinked endpoints, compound chains) where
no fixed pattern could ever cover the space. Neither layer is trusted
alone; a finding only exists where both agree, twice.

---

*Questions not covered here? Open an issue, or ask — this document is
meant to grow with real questions people actually ask, not to be written
once and left stale.*
