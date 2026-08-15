from fastapi import FastAPI

from app.api.routes import (
    auth,
    business_rules,
    credentials,
    organizations,
    projects,
    review_candidates,
    scans,
    targets,
    traffic_import,
    versions,
)

app = FastAPI(title="Verdikt API", version="0.1.0")

app.include_router(auth.router)
app.include_router(organizations.router)
app.include_router(projects.router)
app.include_router(versions.router)
app.include_router(targets.router)
app.include_router(credentials.router)
app.include_router(traffic_import.router)
app.include_router(scans.router)
app.include_router(review_candidates.router)
app.include_router(business_rules.router)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
