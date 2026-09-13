# docker-compose.yml has referenced `build: ./backend` since Phase 0,
# but no Dockerfile ever existed here — `docker compose up` failed
# outright for the backend service. This is the first real one.
FROM python:3.12-slim

# Playwright launches real Chromium for several agents (clickjacking/
# XSS/DOM-XSS/prototype-pollution/stored-XSS browser-proofs, the login
# macro recorder) — this isn't optional for the app to actually work,
# so its system dependencies are installed at image-build time, not
# left as a "figure it out later" runtime surprise.
# S&P Global's network TLS-inspects outbound HTTPS via Zscaler, re-signing
# every connection (PyPI, the Playwright Chromium CDN download, ...) with
# its own root CA. Without it in the trust store, `uv sync` and
# `playwright install` fail cert validation. update-ca-certificates covers
# uv/rustls and Python's own ssl module; SSL_CERT_FILE/REQUESTS_CA_BUNDLE
# below cover anything using certifi's bundled CA list instead of the OS
# store (e.g. requests/httpx as a fallback).
COPY zscaler-root-ca.crt /usr/local/share/ca-certificates/zscaler-root-ca.crt
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt

# Login-macro recording (app.agents.macro.MacroRecorder, headless=False)
# launches a real, visible browser window — with no display in this
# container, that used to just fail. Rather than requiring a browser
# extension (blocked by some orgs' Chrome/Edge enterprise policy —
# ExtensionInstallSources et al, which no file this image builds can
# override), give it a real virtual display and stream it into the
# analyst's own already-open Verdikt tab over VNC-in-browser: Xvfb is
# the virtual framebuffer Chromium renders into; fluxbox is a minimal
# window manager (so the recorded browser window actually has a
# clickable titlebar/close button — bare Xvfb has no window decorations
# at all, and MacroRecorder.record() waits for the Page's "close" event);
# x11vnc mirrors that display over VNC; the `novnc` package bundles
# both websockify (bridges a browser WebSocket to x11vnc's raw VNC
# socket — browsers can't speak raw VNC/RFB directly) and noVNC's own
# static HTML/JS client, so nothing needs fetching from a CDN at
# runtime. procps provides pgrep, which start-display.sh uses to
# confirm each of the above actually stayed running after launch (not
# in this base image by default — python:3.12-slim). See
# start-display.sh and docker-compose.yml's backend.ports.
RUN apt-get update && apt-get install -y --no-install-recommends \
    xvfb \
    x11vnc \
    fluxbox \
    novnc \
    procps \
    && rm -rf /var/lib/apt/lists/*
ENV DISPLAY=:99

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
# noVNC/websockify — see start-display.sh. Only meaningful bound to
# 127.0.0.1 on the host (docker-compose.yml's port mapping, not this
# EXPOSE line) since x11vnc runs with -nopw.
EXPOSE 6080

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
CMD ["sh", "-c", "sh scripts/start-display.sh && uv run alembic upgrade head && uv run uvicorn app.main:app --host 0.0.0.0 --port 8000 --loop asyncio"]
