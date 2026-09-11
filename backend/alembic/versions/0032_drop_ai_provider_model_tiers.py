"""drop ai provider model tiers

Removes ai_provider_configs.model_reasoning and .model_classification —
the manual "route different agent roles to different models" feature
(app.ai.model_routing.ModelRouter / the Account page's "Route models by
task" control) has been removed entirely. Every agent in a scan now
uses the one model configured on the resolved AIProviderConfig (or the
deployment-wide AI_MODEL setting) — no per-task manual model routing to
configure or maintain.

Revision ID: 0032_drop_ai_provider_model_tiers
Revises: 0031_drop_spark_specific_columns
Create Date: 2026-09-11 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0032_drop_ai_provider_model_tiers'
down_revision: Union[str, None] = '0031_drop_spark_specific_columns'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_column("ai_provider_configs", "model_classification")
    op.drop_column("ai_provider_configs", "model_reasoning")


def downgrade() -> None:
    op.add_column("ai_provider_configs", sa.Column("model_reasoning", sa.String(length=100), nullable=True))
    op.add_column("ai_provider_configs", sa.Column("model_classification", sa.String(length=100), nullable=True))
