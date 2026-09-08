# Verdikt

AI multi-agent web application & API security testing platform. A single scan
run executes a 24-node LangGraph DAG of detection agents (SQLi, XSS, access
control, business logic, SSRF, file upload, and the rest of the OWASP Top 10
plus the PortSwigger Web Security Academy topic list), each combining
deterministic HTTP-level probing with LLM-assisted triage and adversarial
validation so only confirmed findings — never hunches — make it into a
report. The frontend covers the full engagement workflow end to end:
projects/versions/scope/targets/credentials, scan runs and their findings,
retest/rescan, a native VGS report-builder workspace, and org-wide
account settings (SSO, ticketing, notifications, CMDB, branding, AI provider
configuration).

See [`docs/BUILD_SPEC.md`](docs/BUILD_SPEC.md) for the original governing
product spec, and
[`docs/architecture-overview/`](docs/architecture-overview/) for a full,
code-verified architecture reference (data model, every API route, every
check ID, every migration, RBAC matrix, and an honest delta against the
original spec) in Markdown/HTML/DOCX, plus a presentation deck and Miro-
importable diagrams.

## Stack

- Backend: Python 3.11+, FastAPI, SQLAlchemy 2.0, Alembic, Postgres (default) via `uv`.
- Frontend: Vite + React + TypeScript + TanStack Query + React Router + Tailwind CSS.
- Local dev DB: Docker Compose Postgres.

## Local development

```bash
cp .env.example backend/.env   # adjust as needed
docker compose up -d db
cd backend
uv sync
uv run alembic upgrade head
uv run uvicorn app.main:app --reload --loop asyncio
```

`--loop asyncio` is required, not optional: uvicorn's default loop
selection silently picks `uvloop` (pulled in by `uvicorn[standard]`)
whenever it's importable, and Playwright's async API is incompatible
with uvloop — `browser.launch()` hangs forever instead of raising,
which permanently stalls the clickjacking/DOM-XSS/prototype-pollution
checks (they use real headless-browser proofs) with no visible error.

API docs at http://localhost:8000/docs once running.

In a second terminal:

```bash
cd frontend
npm install
npm run dev
```

The frontend runs at http://localhost:5173 and talks to the API at
http://localhost:8000 (see `frontend/.env`'s `VITE_API_BASE_URL`). The backend's
`frontend_origin` setting (`app/config.py`) must match the frontend's own origin for
CORS — both default to `http://localhost:5173`.

### Or: everything via Docker Compose

```bash
cp .env.example backend/.env   # optional — see the AI provider note below
docker compose up --build
```

That's it — no separate migration step. Starts Postgres, the backend, and the
frontend dev server together, verified end to end against a completely fresh
setup (empty Postgres volume, no host `.venv`/`node_modules`):

- `backend/Dockerfile` and `frontend/Dockerfile` build real images (the backend
  image also installs Playwright's Chromium, which several agents launch a real
  browser through).
- The backend service runs `alembic upgrade head` automatically before serving
  on every start (a no-op once already current), so a brand-new database gets
  its schema without any manual step.
- Everything here is plain Docker/Compose with no macOS-specific paths or
  behavior, so the same `docker compose up --build` is expected to work
  unchanged on Linux and Windows (via Docker Desktop, WSL2 backend or native).
  If you hit a platform-specific snag, it's worth a bug report — this isn't
  meant to be macOS-only.
- **AI-assisted findings need a real model configured.** `AI_PROVIDER`
  defaults to `fake` (a no-op adapter), so a fresh checkout with no `.env`
  runs end to end but every LLM-triaged check (injection/XSS/access-control/
  etc.) finds nothing — a demo will look empty. There are two ways to fix
  that, and the UI path is the one to use for a demo:
  - **UI-only (recommended):** log in, go to **Account → AI Provider
    Configs**, add a config for Claude/OpenAI/Gemini/Grok or any in-house
    OpenAI-chat-completions-compatible endpoint, and click **Set as
    default**. Every scan that doesn't pick a different provider explicitly
    routes through it from then on — no `.env` editing, no restart, no
    redeploy. This is how to point Verdikt at an internal/self-hosted LLM
    when a Claude/OpenAI key isn't available.
  - **`.env` (deployment-wide fallback):** set `AI_PROVIDER=claude` +
    `ANTHROPIC_API_KEY` (or `AI_PROVIDER=openai` / `AI_PROVIDER=custom` +
    the matching `CUSTOM_LLM_*` settings) in `backend/.env`. This is only
    consulted when a scan has no per-org default configured in the UI.
- Postgres data lives in a named Docker volume (`verdikt_pgdata`), so it
  starts genuinely empty on a fresh clone and persists across
  `docker compose up`/`down` (not `down -v`) on the same machine.
- **Already running a native Postgres on this machine?** Create a
  git-ignored `docker-compose.override.yml` (auto-loaded by `docker compose`
  with no extra flags) that repoints the `backend` service's
  `DATABASE_URL` at `host.docker.internal` plus an `extra_hosts:
  ["host.docker.internal:host-gateway"]` entry (needed on native Linux
  Docker Engine; built into Docker Desktop on macOS/Windows). A fresh clone
  with no such file gets the base compose file's own clean, self-contained
  Postgres — this override is machine-local by design, never committed.

## Tests

The DB layer is intentionally dialect-agnostic (SQLAlchemy ORM only, no Postgres-only
column types), so the test suite runs against an ephemeral SQLite database with no
external services required:

```bash
cd backend
uv sync
uv run pytest
```

Postgres via Docker Compose remains the documented default for real dev/staging/prod
use (see `docker-compose.yml`); the migrations in `alembic/` target Postgres.

As of this writing the suite is **99 files / 527 collected tests**
(`uv run pytest --collect-only -q` to reproduce the count), built on real
fixtures over mocks wherever practical — local HTTP servers standing in for
a target app, a real headless browser for execution proofs, real
cryptographic round-trips for the credential vault.

## Repo layout

```
backend/
  app/
    agents/      41 files — the 24-node LangGraph scan DAG (recon, injection,
                 xss, access_control, business_logic, ssrf, file_upload, ...)
                 plus shared infra (ScopedHttpClient, the credential matrix,
                 retest, task tracking)
    ai/          AIProviderAdapter interface + Claude/OpenAI/Gemini/Grok/
                 GenericOpenAI/Null adapters, provider resolution, budget cap
    checks/      YAML check catalogs (severity/CWE per check ID)
    integrations/ Jira, Slack, Teams (+ bot), Outlook, Burp, CMDB, VGS,
                 PortSwigger scraper
    reporting/   HTML/PDF/DOCX/CSV/JSON report generation, executive summary,
                 finding grouping
    db/          DatabaseAdapter ABC + Postgres/SQLAlchemy implementation
    storage/     ObjectStorageAdapter ABC + local-disk implementation
    models/      SQLAlchemy ORM models (Organization -> Project -> Version -> ...)
    schemas/     Pydantic API contracts
    auth/        Password hashing, JWT, SAML/OIDC SSO, RBAC permission-matrix
    vault/       KMSAdapter ABC + credential envelope encryption
    importers/   TrafficImporter ABC + HAR/Burp/Zest importers
    api/routes/  28 FastAPI route modules
  alembic/       Migrations (schema + seeded role_permissions matrix)
  tests/         pytest suite (99 files / 527 tests)
frontend/
  src/
    api/         Hand-written typed fetch client + TS types mirroring app/schemas
    auth/        AuthContext (JWT bearer token, current user, RBAC-aware canWrite/canReview)
    components/  Layout, ProtectedRoute, Tabs, badges
    pages/       Projects -> Version workspace (scope/targets/credentials/
                 business rules/scan runs) -> Scan Run detail (agent jobs/
                 findings/review candidates/reports); account/ (SSO, ticketing,
                 notifications, CMDB, branding, AI provider configs); vgs/
                 (the native VGS report-builder workspace)
docs/
  BUILD_SPEC.md            Original governing product spec
  architecture-overview/   Full code-verified architecture reference,
                           presentation deck, and Miro-importable diagrams
```

## Security notes

- Every `Version` (engagement) carries `ScopeEntry` rows — a hard, exact
  host+port allow-list every agent enforces on every request
  (`app.agents.scope.is_in_scope`), not just a UI reminder. Adding a Target
  auto-derives its matching Scope entry, so a host only ever needs to be
  typed once.
- Credential secrets are envelope-encrypted via `KMSAdapter` before hitting the
  database and are only ever returned to API clients as a masked reference —
  the same pattern is reused across every integration's stored secret
  (AI provider keys, CMDB/ticketing/notification/VGS credentials, OIDC client
  secrets). `LocalKMSAdapter` (Fernet, keyed by `VAULT_MASTER_KEY`) is
  dev-only — production must implement a real KMS-backed adapter (an AWS KMS
  adapter is already available via `KMS_PROVIDER=aws`).
- RBAC is a real `role_permissions` DB table (19 resources × 4 actions;
  org_admin / project_lead / analyst / viewer), not hardcoded role checks,
  so new roles/permissions are data, not code.
- There is deliberately **no pre-scan authorization-letter gate** — an
  earlier version of this had one (requiring an uploaded authorization
  attestation before any active testing could run) and it was removed;
  scope enforcement above is the real, enforced technical control. Treat
  scoping a `Version` correctly as a hard requirement before scanning
  anything you don't own.
