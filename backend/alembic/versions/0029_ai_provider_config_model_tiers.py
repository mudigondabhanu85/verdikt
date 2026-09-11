"""ai provider config model tiers

Adds ai_provider_configs.model_reasoning and .model_classification
(both nullable) — optional per-tier overrides so different agent roles
can be routed to different models on the same provider account (see
app.ai.model_routing.ModelRouter). Left unset, `model` is used for
every tier, exactly matching pre-migration behavior.

Revision ID: 0029_ai_provider_config_model_tiers
Revises: 0028_credential_privilege_rank
Create Date: 2026-09-10 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0029_ai_provider_config_model_tiers'
down_revision: Union[str, None] = '0028_credential_privilege_rank'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "ai_provider_configs", sa.Column("model_reasoning", sa.String(length=100), nullable=True)
    )
    op.add_column(
        "ai_provider_configs", sa.Column("model_classification", sa.String(length=100), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("ai_provider_configs", "model_classification")
    op.drop_column("ai_provider_configs", "model_reasoning")
