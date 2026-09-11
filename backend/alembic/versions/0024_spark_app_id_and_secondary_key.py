"""spark app id and secondary key

Adds ai_provider_configs.app_id (nullable — only meaningful for
provider="spark", overriding the deployment-wide SPARK_APP_ID setting)
and .encrypted_secondary_api_key (nullable — a second Spark API key an
org can register alongside the primary one, so SparkAdapter can retry
once on a 401 with the secondary key before failing the call outright,
same rationale as dast-automation's primary/secondary key rotation).
Both are optional on every other provider; Spark is the only one that
currently reads either.

Revision ID: 0024_spark_app_id_and_secondary_key
Revises: 0023_ai_provider_config_default
Create Date: 2026-09-08 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0024_spark_app_id_and_secondary_key'
down_revision: Union[str, None] = '0023_ai_provider_config_default'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("ai_provider_configs", sa.Column("app_id", sa.String(length=100), nullable=True))
    op.add_column(
        "ai_provider_configs", sa.Column("encrypted_secondary_api_key", sa.LargeBinary(), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("ai_provider_configs", "encrypted_secondary_api_key")
    op.drop_column("ai_provider_configs", "app_id")
