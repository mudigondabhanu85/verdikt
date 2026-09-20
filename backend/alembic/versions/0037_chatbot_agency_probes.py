"""chatbot agency probes

Adds chatbot_agency_probes (§ Chatbot/LLM Pentest Phase 2 — LLM03
Excessive Agency, see app.agents.chatbot_injection): an analyst's
plain-language description of an action one specific ChatbotTarget
should never agree to/perform. Same "row per testable thing, FK to its
parent, created_by for audit" shape as business_rules (0004), scoped to
one ChatbotTarget rather than a whole Version. No RBAC seed needed here
— this is a sub-resource of "chatbot_target" (0036 already seeded those
grants), the same way VgsEvidenceStep reuses "vgs_vulnerability"
permissions instead of getting its own resource.

Revision ID: 0037_chatbot_agency_probes
Revises: 0036_chatbot_targets
Create Date: 2026-09-18 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0037_chatbot_agency_probes'
down_revision: Union[str, None] = '0036_chatbot_targets'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'chatbot_agency_probes',
        sa.Column('chatbot_target_id', sa.Uuid(), nullable=False),
        sa.Column('forbidden_action', sa.Text(), nullable=False),
        sa.Column('created_by', sa.Uuid(), nullable=True),
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['chatbot_target_id'], ['chatbot_targets.id'], ),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )


def downgrade() -> None:
    op.drop_table('chatbot_agency_probes')
