"""credential privilege rank

Adds credential_sets.privilege_rank (nullable, analyst-set — higher
means more privileged) — enables a genuine role-vs-role vertical
privilege escalation check (app.agents.access_control's new
_detect_role_vertical): does a lower-ranked authenticated identity get
the same response as a higher-ranked one on the same endpoint? Distinct
from the existing "vertical" check, which only ever compares
unauthenticated vs. authenticated — there was no check at all before
this for two different authenticated roles.

Revision ID: 0028_credential_privilege_rank
Revises: 0027_business_rule_source
Create Date: 2026-09-10 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0028_credential_privilege_rank'
down_revision: Union[str, None] = '0027_business_rule_source'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("credential_sets", sa.Column("privilege_rank", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("credential_sets", "privilege_rank")
