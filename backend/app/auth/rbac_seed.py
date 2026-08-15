"""Baseline RBAC permission matrix (§9). This is the single source of truth
for the role_permissions seed data — both the Alembic migrations (production
schema bootstrap) and the test fixtures (SQLite-backed test DB) build the
same rows from this, so the two never drift apart.
"""

RESOURCES = ("organization", "project", "version", "target", "credential", "traffic", "scan")
ACTIONS = ("create", "read", "update", "delete")


def baseline_grants() -> list[tuple[str, str, str]]:
    """Returns (role, resource, action) tuples to seed as allowed=True."""
    grants: list[tuple[str, str, str]] = []

    # org_admin: unrestricted.
    for resource in RESOURCES:
        for action in ACTIONS:
            grants.append(("org_admin", resource, action))

    # project_lead: full CRUD on engagement resources; read-only on the org itself.
    grants.append(("project_lead", "organization", "read"))
    for resource in ("project", "version", "target", "credential", "traffic", "scan"):
        for action in ACTIONS:
            grants.append(("project_lead", resource, action))

    # analyst: read everywhere, plus create on traffic/scan (runs imports/scans).
    for resource in RESOURCES:
        grants.append(("analyst", resource, "read"))
    grants.append(("analyst", "traffic", "create"))
    grants.append(("analyst", "scan", "create"))

    # viewer: read-only everywhere.
    for resource in RESOURCES:
        grants.append(("viewer", resource, "read"))

    return grants


def scan_resource_grants() -> list[tuple[str, str, str]]:
    """Just the "scan" resource rows — used by the incremental migration
    0002, which runs against DBs that already have every other resource's
    rows seeded by 0001 and must not re-insert them (unique constraint)."""
    return [g for g in baseline_grants() if g[1] == "scan"]
