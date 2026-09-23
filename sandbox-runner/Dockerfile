# Deliberately its own image, not sharing backend/'s much larger
# dependency tree — see app/main.py's module docstring for why this
# service exists at all and why it's kept this small.
FROM python:3.12-slim

# The `docker` CLI itself is not required (the docker Python SDK talks
# to the socket directly via its own HTTP-over-unix-socket client), but
# curl is used by the healthcheck below.
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

WORKDIR /app

COPY pyproject.toml ./
RUN uv sync --no-install-project

COPY . .
RUN uv sync

EXPOSE 8090

CMD ["uv", "run", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8090"]
