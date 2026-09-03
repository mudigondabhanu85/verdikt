import asyncio
import concurrent.futures
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import (
    ai_provider_configs,
    api_keys,
    auth,
    burp,
    business_rules,
    cmdb_configs,
    credentials,
    dashboard,
    finding_tickets,
    notification_configs,
    objects,
    oidc,
    organizations,
    projects,
    retest_jobs,
    review_candidates,
    scans,
    targets,
    ticketing_configs,
    traffic_import,
    versions,
    vgs_configs,
)
from app.config import get_settings

@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Defensive hardening from §14 live validation against OWASP Juice
    # Shop (see docs/VALIDATION_SCORECARD.md fix #9) — built while
    # chasing a real intermittent scan stall whose actual root cause
    # turned out to be unrelated (a NUL-byte-vs-Postgres bug, fix #8).
    # asyncio's default thread-pool executor — used internally for DNS
    # resolution (loop.getaddrinfo) and every asyncio.to_thread call
    # (e.g. app.agents.http_client.probe_tls_version) — defaults to a
    # small size (min(32, cpu_count+4); 19 on a typical dev machine),
    # small enough that a real scan's true concurrent fan-out (14+
    # agents) could plausibly exhaust it under real-world conditions.
    # Kept as cheap, harmless headroom even though it wasn't what fixed
    # the bug this round.
    asyncio.get_running_loop().set_default_executor(
        concurrent.futures.ThreadPoolExecutor(max_workers=256)
    )
    yield


app = FastAPI(title="Verdikt API", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[get_settings().frontend_origin],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(organizations.router)
app.include_router(ai_provider_configs.router)
app.include_router(oidc.router)
app.include_router(api_keys.router)
app.include_router(projects.router)
app.include_router(versions.router)
app.include_router(targets.router)
app.include_router(credentials.router)
app.include_router(traffic_import.router)
app.include_router(scans.router)
app.include_router(review_candidates.router)
app.include_router(business_rules.router)
app.include_router(burp.router)
app.include_router(objects.router)
app.include_router(retest_jobs.router)
app.include_router(dashboard.router)
app.include_router(notification_configs.router)
app.include_router(ticketing_configs.router)
app.include_router(finding_tickets.router)
app.include_router(cmdb_configs.router)
app.include_router(vgs_configs.router)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
