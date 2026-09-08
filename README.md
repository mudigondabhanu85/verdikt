# Verdikt

AI multi-agent web application & API security testing platform. See
[`docs/BUILD_SPEC.md`](docs/BUILD_SPEC.md) for the full governing product spec. The backend
implements the full agent/scanning/reporting
pipeline (recon through a broad §3 vulnerability taxonomy, retest, enterprise
hardening); the frontend (§7) is a first-pass web UI covering the core engagement
workflow end to end.

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
- **AI-assisted findings need a real API key.** `AI_PROVIDER` defaults to
  `fake` (a no-op adapter), so a fresh checkout with no `.env` runs end to end
  but every LLM-triaged check (injection/XSS/access-control/etc.) finds
  nothing — a demo will look empty. Set `AI_PROVIDER=claude` and
  `ANTHROPIC_API_KEY` in `backend/.env` (copied from `.env.example`) before a
  real demo.
- Postgres data lives in a named Docker volume (`verdikt_pgdata`), so it
  starts genuinely empty on a fresh clone and persists across
  `docker compose up`/`down` (not `down -v`) on the same machine.

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

## Repo layout

```
backend/
  app/
    db/          DatabaseAdapter ABC + Postgres/SQLAlchemy implementation
    storage/     ObjectStorageAdapter ABC + local-disk implementation
    models/      SQLAlchemy ORM models (Organization -> Project -> Version -> ...)
    schemas/     Pydantic API contracts, incl. the canonical HttpInteraction schema
    auth/        Password hashing, JWT, RBAC permission-matrix enforcement
    vault/       KMSAdapter ABC + credential envelope encryption
    importers/   TrafficImporter ABC + HarImporter
    api/         FastAPI routes
  alembic/       Migrations (schema + seeded role_permissions matrix)
  tests/         pytest suite
frontend/
  src/
    api/         Hand-written typed fetch client + TS types mirroring app/schemas
    auth/        AuthContext (JWT bearer token, current user, RBAC-aware canWrite/canReview)
    components/  Layout, ProtectedRoute, Tabs, badges
    pages/       Projects -> Version workspace (scope/targets/credentials/
                 business rules/scan runs) -> Scan Run detail (agent jobs/findings/
                 review candidates/reports)
```

## Security notes (Phase 0 scope)

- Every `Version` (engagement) carries `ScopeEntry` rows — a hard, exact
  host+port allow-list every agent enforces on every request
  (`app.agents.scope.is_in_scope`), not just a UI reminder. Adding a Target
  auto-derives its matching Scope entry, so a host only ever needs to be
  typed once.
- Credential secrets are envelope-encrypted via `KMSAdapter` before hitting the
  database and are only ever returned to API clients as a masked reference.
  `LocalKMSAdapter` (Fernet, keyed by `VAULT_MASTER_KEY`) is dev-only — production
  must implement a real KMS-backed adapter.
- RBAC is a real `role_permissions` DB table (org_admin / project_lead / analyst /
  viewer), not hardcoded role checks, so new roles/permissions are data, not code.
