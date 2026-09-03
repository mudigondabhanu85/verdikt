"""Baseline RBAC permission matrix (§9). This is the single source of truth
for the role_permissions seed data — both the Alembic migrations (production
schema bootstrap) and the test fixtures (SQLite-backed test DB) build the
same rows from this, so the two never drift apart.
"""

RESOURCES = (
    "organization",
    "project",
    "version",
    "target",
    "credential",
    "traffic",
    "scan",
    "review_candidate",
    "business_rule",
    "ai_provider_config",
    "oidc_provider_config",
    "notification_config",
    "ticketing_config",
    "cmdb_config",
    "vgs_config",
)
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
    for resource in (
        "project",
        "version",
        "target",
        "credential",
        "traffic",
        "scan",
        "review_candidate",
        "business_rule",
        "ai_provider_config",
        "oidc_provider_config",
        "notification_config",
        "ticketing_config",
        "cmdb_config",
        "vgs_config",
    ):
        for action in ACTIONS:
            grants.append(("project_lead", resource, action))

    # analyst: read everywhere, plus create on traffic/scan/business_rule
    # (runs imports/scans, defines business rules) and update on
    # review_candidate (promotes/dismisses candidates).
    for resource in RESOURCES:
        grants.append(("analyst", resource, "read"))
    grants.append(("analyst", "traffic", "create"))
    grants.append(("analyst", "scan", "create"))
    grants.append(("analyst", "review_candidate", "update"))
    grants.append(("analyst", "business_rule", "create"))

    # viewer: read-only everywhere.
    for resource in RESOURCES:
        grants.append(("viewer", resource, "read"))

    return grants


def _grants_for_resource(resource: str) -> list[tuple[str, str, str]]:
    return [g for g in baseline_grants() if g[1] == resource]


def scan_resource_grants() -> list[tuple[str, str, str]]:
    """Just the "scan" resource rows — used by the incremental migration
    0002, which runs against DBs that already have every other resource's
    rows seeded by 0001 and must not re-insert them (unique constraint)."""
    return _grants_for_resource("scan")


def review_candidate_resource_grants() -> list[tuple[str, str, str]]:
    """Just the "review_candidate" resource rows — used by the incremental
    migration 0003, same reasoning as scan_resource_grants() above."""
    return _grants_for_resource("review_candidate")


def business_rule_resource_grants() -> list[tuple[str, str, str]]:
    """Just the "business_rule" resource rows — used by the incremental
    migration 0004, same reasoning as scan_resource_grants() above."""
    return _grants_for_resource("business_rule")


def ai_provider_config_resource_grants() -> list[tuple[str, str, str]]:
    """Just the "ai_provider_config" resource rows — used by the
    incremental migration adding this resource, same reasoning as
    scan_resource_grants() above."""
    return _grants_for_resource("ai_provider_config")


def oidc_provider_config_resource_grants() -> list[tuple[str, str, str]]:
    """Just the "oidc_provider_config" resource rows — used by the
    incremental migration adding this resource, same reasoning as
    scan_resource_grants() above."""
    return _grants_for_resource("oidc_provider_config")


def notification_config_resource_grants() -> list[tuple[str, str, str]]:
    """Just the "notification_config" resource rows — used by the
    incremental migration adding this resource, same reasoning as
    scan_resource_grants() above."""
    return _grants_for_resource("notification_config")


def ticketing_config_resource_grants() -> list[tuple[str, str, str]]:
    """Just the "ticketing_config" resource rows — used by the
    incremental migration adding this resource, same reasoning as
    scan_resource_grants() above."""
    return _grants_for_resource("ticketing_config")


def cmdb_config_resource_grants() -> list[tuple[str, str, str]]:
    """Just the "cmdb_config" resource rows — used by the incremental
    migration adding this resource, same reasoning as
    scan_resource_grants() above."""
    return _grants_for_resource("cmdb_config")


def vgs_config_resource_grants() -> list[tuple[str, str, str]]:
    """Just the "vgs_config" resource rows — used by the incremental
    migration adding this resource, same reasoning as
    scan_resource_grants() above."""
    return _grants_for_resource("vgs_config")
