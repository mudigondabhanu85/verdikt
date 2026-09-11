"""ai provider config secret rotated at

Adds ai_provider_configs.secret_rotated_at (nullable) — set whenever
the secret is created/rotated, so the UI can show a real "expires at"
countdown for Spark's ~60-minute bearer tokens instead of the token
silently going stale mid-scan with no visible warning.

Revision ID: 0030_ai_provider_config_secret_rotated_at
Revises: 0029_ai_provider_config_model_tiers
Create Date: 2026-09-10 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0030_ai_provider_config_secret_rotated_at'
down_revision: Union[str, None] = '0029_ai_provider_config_model_tiers'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "ai_provider_configs", sa.Column("secret_rotated_at", sa.DateTime(timezone=True), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("ai_provider_configs", "secret_rotated_at")
