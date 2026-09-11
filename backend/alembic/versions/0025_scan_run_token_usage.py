"""scan run token usage

Adds scan_runs.llm_input_tokens / llm_output_tokens — running totals of
actual token usage across every LLM call a scan run made, accumulated
alongside the existing llm_cost_usd in app.ai.budget.BudgetGuard.
guarded_complete. Lets a scan run's "how many tokens / what did it cost"
be answered directly instead of only having the dollar total, and only
that total being untracked-in-tokens.

Revision ID: 0025_scan_run_token_usage
Revises: 0024_spark_app_id_and_secondary_key
Create Date: 2026-09-09 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0025_scan_run_token_usage'
down_revision: Union[str, None] = '0024_spark_app_id_and_secondary_key'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scan_runs", sa.Column("llm_input_tokens", sa.BigInteger(), nullable=False, server_default="0")
    )
    op.add_column(
        "scan_runs", sa.Column("llm_output_tokens", sa.BigInteger(), nullable=False, server_default="0")
    )
    op.alter_column("scan_runs", "llm_input_tokens", server_default=None)
    op.alter_column("scan_runs", "llm_output_tokens", server_default=None)


def downgrade() -> None:
    op.drop_column("scan_runs", "llm_output_tokens")
    op.drop_column("scan_runs", "llm_input_tokens")
