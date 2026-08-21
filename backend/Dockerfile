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
CMD ["uv", "run", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
