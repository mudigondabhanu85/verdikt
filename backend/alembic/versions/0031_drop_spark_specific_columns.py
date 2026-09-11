"""drop spark specific columns

Removes ai_provider_configs.app_id and .encrypted_secondary_api_key —
these were added in 0024 for a SparkAdapter (S&P Global's internal LLM
gateway) that has since been removed entirely: it was specific to one
org's internal infrastructure, not a generally-useful provider for this
project. The other columns 0024's sibling migrations added
(model_reasoning/model_classification in 0029, secret_rotated_at in
0030) are genuinely provider-agnostic and stay.

Revision ID: 0031_drop_spark_specific_columns
Revises: 0030_ai_provider_config_secret_rotated_at
Create Date: 2026-09-10 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0031_drop_spark_specific_columns'
down_revision: Union[str, None] = '0030_ai_provider_config_secret_rotated_at'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_column("ai_provider_configs", "encrypted_secondary_api_key")
    op.drop_column("ai_provider_configs", "app_id")


def downgrade() -> None:
    op.add_column("ai_provider_configs", sa.Column("app_id", sa.String(length=100), nullable=True))
    op.add_column(
        "ai_provider_configs", sa.Column("encrypted_secondary_api_key", sa.LargeBinary(), nullable=True)
    )
