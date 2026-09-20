"""chatbot targets

Adds chatbot_targets (§ Chatbot/LLM Pentest Phase 1 — see
app.agents.chatbot_injection): an analyst-configured conversational
endpoint (no auto-discovery is possible for "this endpoint is a chat
interface"), following the same shape as business_rules (0004) and
cmdb_configs — a version-scoped resource with an optional envelope-
encrypted auth header.

Revision ID: 0036_chatbot_targets
Revises: 0035_evidence_payload
Create Date: 2026-09-18 00:00:00.000000

"""
import uuid
from datetime import datetime, timezone
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

from app.auth.rbac_seed import chatbot_target_resource_grants


# revision identifiers, used by Alembic.
revision: str = '0036_chatbot_targets'
down_revision: Union[str, None] = '0035_evidence_payload'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _seed_chatbot_target_permissions() -> None:
    """Incremental grants for the new "chatbot_target" resource, same
    reasoning as 0004's business_rule seed: every other resource is
    already seeded, so this inserts only the new rows."""
    role_permissions = sa.table(
        "role_permissions",
        sa.column("id", sa.Uuid()),
        sa.column("role", sa.String()),
        sa.column("resource", sa.String()),
        sa.column("action", sa.String()),
        sa.column("allowed", sa.Boolean()),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )
    now = datetime.now(timezone.utc)
    rows = [
        {
            "id": uuid.uuid4(),
            "role": role,
            "resource": resource,
            "action": action,
            "allowed": True,
            "created_at": now,
        }
        for role, resource, action in chatbot_target_resource_grants()
    ]
    op.bulk_insert(role_permissions, rows)


def upgrade() -> None:
    op.create_table(
        'chatbot_targets',
        sa.Column('version_id', sa.Uuid(), nullable=False),
        sa.Column('label', sa.String(length=200), nullable=False),
        sa.Column('endpoint_url', sa.String(length=500), nullable=False),
        sa.Column('http_method', sa.String(length=10), nullable=False),
        sa.Column('request_body_template', sa.Text(), nullable=False),
        sa.Column('content_type', sa.String(length=100), nullable=False),
        sa.Column('response_text_path', sa.String(length=200), nullable=False),
        sa.Column('auth_header_name', sa.String(length=100), nullable=True),
        sa.Column('encrypted_auth_header_value', sa.LargeBinary(), nullable=True),
        sa.Column('masked_reference', sa.String(length=255), nullable=True),
        sa.Column('created_by', sa.Uuid(), nullable=True),
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
        sa.ForeignKeyConstraint(['version_id'], ['versions.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )

    _seed_chatbot_target_permissions()


def downgrade() -> None:
    role_permissions = sa.table("role_permissions", sa.column("resource", sa.String()))
    op.execute(role_permissions.delete().where(role_permissions.c.resource == "chatbot_target"))

    op.drop_table('chatbot_targets')
