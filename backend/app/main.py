import asyncio
import concurrent.futures
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import (
    ai_provider_configs,
    api_keys,
    attack_chains,
    auth,
    burp,
    business_rules,
    cmdb_configs,
    credentials,
    dashboard,
    finding_tickets,
    findings,
    macro_upload,
    notification_configs,
    objects,
    oidc,
    org_branding,
    organizations,
    projects,
    retest_jobs,
    review_candidates,
    saml,
    scans,
    targets,
    ticketing_configs,
    traffic_import,
    users,
    versions,
    vgs_configs,
    vgs_vulnerabilities,
)
from app.config import get_settings

# Without this, the root logger defaults to WARNING with no handler
# attached, so every logger.info(...) call anywhere in app/* (e.g. the
# AI-provider resolution tracing in app/ai/provider.py) is silently
# dropped and never reaches `docker compose logs backend` — confirmed
# missing during a real incident chasing an AI provider misconfig.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

logger = logging.getLogger(__name__)


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


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    # Without this, an unhandled exception falls through to Starlette's
    # default ServerErrorMiddleware, which returns a bare 500 with no
    # Access-Control-Allow-Origin header. The browser then reports
    # "blocked by CORS policy" instead of the real error, which is
    # exactly as misleading for a genuine backend bug (e.g. the
    # in-container Playwright headed-browser launch in
    # app.api.routes.credentials.start_recording_macro, or any future
    # unexpected 500) as it would be for an actual CORS misconfiguration
    # — undistinguishable from the browser's console alone. A route
    # handler's own registered @app.exception_handler(SomeSpecificError)
    # (if any) still takes precedence over this catch-all; this only
    # catches what nothing more specific already handled.
    #
    # Registering this handler is NOT enough by itself: Starlette installs
    # a bare-Exception handler into ServerErrorMiddleware, which is the
    # outermost layer and wraps CORSMiddleware from the outside — so a
    # response built here still never passes back through CORSMiddleware
    # to get its headers added. The CORS header has to be set by hand,
    # right here, matching what CORSMiddleware itself would have done for
    # this same Origin — an exact allow-list match (this deployment's
    # CORSMiddleware is configured with a specific single allowed origin,
    # never a wildcard), never blindly echoing an arbitrary Origin back.
    logger.exception("Unhandled exception", exc_info=exc)
    response = JSONResponse(status_code=500, content={"detail": "Internal server error"})
    origin = request.headers.get("origin")
    if origin is not None and origin == get_settings().frontend_origin:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
    return response

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
app.include_router(findings.router)
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
app.include_router(users.router)
app.include_router(attack_chains.router)
app.include_router(macro_upload.router)
app.include_router(org_branding.router)
app.include_router(saml.router)
app.include_router(vgs_vulnerabilities.library_router)
app.include_router(vgs_vulnerabilities.draft_router)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
