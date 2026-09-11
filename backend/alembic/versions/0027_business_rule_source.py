"""business rule source

Adds business_rules.source ("analyst" default | "ai_generated") — see
app.agents.business_logic_planner.BusinessLogicPlannerAgent, which
proposes business-logic test hypotheses from the site map/tech-stack
fingerprint instead of requiring an analyst to hand-author every rule.
Provenance/audit only: the detection pipeline (app.agents.business_logic)
treats every rule identically regardless of source — an AI-generated
rule still has to survive the same deterministic-detector -> LLM-triage
-> adversarial-validation gate as an analyst-authored one.

Revision ID: 0027_business_rule_source
Revises: 0026_finding_resource_permissions
Create Date: 2026-09-10 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0027_business_rule_source'
down_revision: Union[str, None] = '0026_finding_resource_permissions'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "business_rules", sa.Column("source", sa.String(length=20), nullable=False, server_default="analyst")
    )
    op.alter_column("business_rules", "source", server_default=None)


def downgrade() -> None:
    op.drop_column("business_rules", "source")
