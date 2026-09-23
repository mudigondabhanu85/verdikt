"""project memberships

Adds per-user, per-project access restriction on top of the existing
org-wide role (app.models.project_membership.ProjectMembership) — a
project_lead/analyst/viewer can now be limited to an explicit set of
Projects within their org; org_admin continues to see every Project
unconditionally (see app.api.deps._check_project_access). No new
role_permissions rows are needed: this is a narrowing filter applied on
top of the existing "project"/"version"/etc. resource grants, not a new
resource of its own.

Revision ID: 0040_project_memberships
Revises: 0039_autonomous_pentest
Create Date: 2026-09-24 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0040_project_memberships'
down_revision: Union[str, None] = '0039_autonomous_pentest'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'project_memberships',
        sa.Column('user_id', sa.Uuid(), nullable=False),
        sa.Column('project_id', sa.Uuid(), nullable=False),
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'project_id', name='uq_project_membership_user_project'),
    )


def downgrade() -> None:
    op.drop_table('project_memberships')
