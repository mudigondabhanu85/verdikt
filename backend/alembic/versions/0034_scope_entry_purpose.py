"""scope entry purpose

Adds scope_entries.purpose (default 'target'). Closes a real scope leak:
app.api.routes.credentials._ensure_login_endpoint_in_scope auto-adds a
ScopeEntry for a login endpoint's host (very often a third-party IdP
like Okta/Auth0, needed so SessionManager's login POST doesn't hit
ScopeViolationError) with in_scope=True — identical, before this
column, to a real Target-derived scope entry. Every detection agent
that fuzzes discovered_endpoints/forms/parameters had no way to tell
"a host the analyst explicitly typed as a scan target" apart from "a
host that got added purely so login could reach it," so a third-party
IdP could end up on the receiving end of injection/XSS/SSTI payloads
just because the crawl happened to discover something on it.

'login_only' entries stay in scope for is_in_scope() (login must still
be able to reach the IdP) — the new column only feeds
app.agents.scope's fuzzing filter, applied where discovered_endpoints/
forms/parameters get produced (app.agents.graph), not the scope
allow-list check itself.

Revision ID: 0034_scope_entry_purpose
Revises: 0033_vgs_auto_seed_finding_memory
Create Date: 2026-09-15 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0034_scope_entry_purpose'
down_revision: Union[str, None] = '0033_vgs_auto_seed_finding_memory'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scope_entries",
        sa.Column("purpose", sa.String(length=20), nullable=False, server_default="target"),
    )
    op.alter_column("scope_entries", "purpose", server_default=None)


def downgrade() -> None:
    op.drop_column("scope_entries", "purpose")
