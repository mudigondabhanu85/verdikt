# Dev-mode image, matching the backend service's --reload pattern in
# docker-compose.yml — runs the real Vite dev server (HMR included),
# not a production build. A production image (multi-stage build ->
# static files served by nginx) is a reasonable follow-up once there's
# an actual deployment target to build it for.
FROM node:22-slim

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .

EXPOSE 5173

# --host 0.0.0.0 is required for the dev server to be reachable from
# outside the container at all — Vite binds to localhost only by default.
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
