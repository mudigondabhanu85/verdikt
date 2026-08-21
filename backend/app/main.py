from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import (
    ai_provider_configs,
    api_keys,
    auth,
    burp,
    business_rules,
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
)
from app.config import get_settings

app = FastAPI(title="Verdikt API", version="0.1.0")

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


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
