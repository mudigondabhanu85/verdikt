# Dev-mode image, matching the backend service's --reload pattern in
# docker-compose.yml — runs the real Vite dev server (HMR included),
# not a production build. A production image (multi-stage build ->
# static files served by nginx) is a reasonable follow-up once there's
# an actual deployment target to build it for.
FROM node:22-slim

WORKDIR /app

# S&P Global's network TLS-inspects outbound HTTPS via Zscaler, re-signing
# every connection (including registry.npmjs.org) with its own root CA.
# The container's trust store doesn't know that CA by default, so `npm ci`
# fails cert validation with UNABLE_TO_GET_ISSUER_CERT_LOCALLY. Installing
# it into the OS trust store AND pointing NODE_EXTRA_CA_CERTS at it is
# required — Node's own TLS stack ignores the OS store and ships its own
# bundled CA list unless told otherwise.
COPY zscaler-root-ca.crt /usr/local/share/ca-certificates/zscaler-root-ca.crt
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*
ENV NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/zscaler-root-ca.crt

COPY package.json package-lock.json ./
# "Exit handler never called!" (npm/cli#4028) is a known npm bug that
# surfaces as a bare `npm ci` failure whenever the registry connection
# gets interrupted mid-install — raising the fetch timeout/retry budget
# makes a transient drop retry-through instead of failing outright.
RUN npm config set fetch-timeout 600000 \
    && npm config set fetch-retries 5 \
    && npm ci

COPY . .

EXPOSE 5173

# --host 0.0.0.0 is required for the dev server to be reachable from
# outside the container at all — Vite binds to localhost only by default.
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
