"""ai provider config default

Adds ai_provider_configs.is_default plus a partial unique index enforcing
at most one default per org — the UI-only path for "any LLM can be
patched in" (§0/§10): an org sets one AIProviderConfig as its default
once, from the Account page, and every scan that doesn't specify its own
provider routes through it automatically. No .env editing required; the
deployment-wide AI_PROVIDER setting remains the final fallback for orgs
that haven't configured one.

Revision ID: 0023_ai_provider_config_default
Revises: 0022_drop_authorization_records
Create Date: 2026-09-08 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0023_ai_provider_config_default'
down_revision: Union[str, None] = '0022_drop_authorization_records'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "ai_provider_configs",
        sa.Column("is_default", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.alter_column("ai_provider_configs", "is_default", server_default=None)
    op.create_index(
        "ix_ai_provider_configs_one_default_per_org",
        "ai_provider_configs",
        ["org_id"],
        unique=True,
        postgresql_where=sa.text("is_default"),
    )


def downgrade() -> None:
    op.drop_index("ix_ai_provider_configs_one_default_per_org", table_name="ai_provider_configs")
    op.drop_column("ai_provider_configs", "is_default")
