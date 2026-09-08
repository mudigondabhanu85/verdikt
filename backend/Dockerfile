# docker-compose.yml has referenced `build: ./backend` since Phase 0,
# but no Dockerfile ever existed here — `docker compose up` failed
# outright for the backend service. This is the first real one.
FROM python:3.12-slim

# Playwright launches real Chromium for several agents (clickjacking/
# XSS/DOM-XSS/prototype-pollution/stored-XSS browser-proofs, the login
# macro recorder) — this isn't optional for the app to actually work,
# so its system dependencies are installed at image-build time, not
# left as a "figure it out later" runtime surprise.
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

WORKDIR /app

# Dependencies first (better layer caching — code changes shouldn't
# force a full reinstall).
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project

COPY . .
RUN uv sync --frozen
RUN uv run playwright install --with-deps chromium

EXPOSE 8000

# docker-compose.yml overrides this with --reload for local dev; this
# default is what runs if the image is ever used standalone (e.g. a
# real deployment, not just docker compose up).
#
# Runs pending migrations before serving — nothing else creates the
# schema, so a fresh database has no tables at all otherwise.
# `alembic upgrade head` is a no-op once already current, so this is
# safe on every container start, not just the first one.
#
# --loop asyncio is required, not optional: uvicorn[standard] pulls in
# uvloop, and uvicorn's default `--loop auto` silently selects it
# whenever it's importable. Playwright's async API is incompatible with
# uvloop — browser.launch() hangs forever (no timeout, no error, no
# subprocess ever spawns) instead of raising, which permanently stalls
# every real-headless-browser check (clickjacking/dom_xss/
# prototype-pollution) with no visible failure. Found via §14 live
# validation against OWASP Juice Shop, where those three AgentJobs
# stayed "running" indefinitely on every real scan until this was set.
CMD ["sh", "-c", "uv run alembic upgrade head && uv run uvicorn app.main:app --host 0.0.0.0 --port 8000 --loop asyncio"]
