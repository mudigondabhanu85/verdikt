"""phase 11 extensibility and lifecycle

Adds: AI provider auth_type + Gemini/Grok support, Teams/Outlook
notification config storage, VGS optional auth fields, project soft
delete (archived_at), user invite lifecycle fields, the "user" RBAC
resource, and the attack_chains / attack_chain_evidence tables (§2 Chain
Analysis Agent).

Revision ID: 0014_phase11_extensibility_and_lifecycle
Revises: 0013_credential_extra_cookies
Create Date: 2026-09-03 06:00:00.000000

"""
import uuid
from datetime import datetime, timezone
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

from app.auth.rbac_seed import user_resource_grants


# revision identifiers, used by Alembic.
revision: str = '0014_phase11_extensibility_and_lifecycle'
down_revision: Union[str, None] = '0013_credential_extra_cookies'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _seed_user_permissions() -> None:
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
        for role, resource, action in user_resource_grants()
    ]
    op.bulk_insert(role_permissions, rows)


def upgrade() -> None:
    op.add_column(
        'ai_provider_configs',
        sa.Column('auth_type', sa.String(length=20), nullable=False, server_default='api_key'),
    )

    op.alter_column('notification_configs', 'encrypted_webhook_url', nullable=True)
    op.add_column(
        'notification_configs', sa.Column('encrypted_config_json', sa.LargeBinary(), nullable=True)
    )

    op.add_column('vgs_configs', sa.Column('auth_type', sa.String(length=20), nullable=True))
    op.add_column(
        'vgs_configs', sa.Column('encrypted_auth_value', sa.LargeBinary(), nullable=True)
    )
    op.add_column(
        'vgs_configs', sa.Column('masked_auth_reference', sa.String(length=255), nullable=True)
    )

    op.add_column(
        'projects', sa.Column('archived_at', sa.DateTime(timezone=True), nullable=True)
    )

    op.add_column('users', sa.Column('invite_token', sa.String(length=64), nullable=True))
    op.create_unique_constraint('uq_users_invite_token', 'users', ['invite_token'])
    op.create_index('ix_users_invite_token', 'users', ['invite_token'])
    op.add_column('users', sa.Column('invited_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        'users', sa.Column('invite_accepted_at', sa.DateTime(timezone=True), nullable=True)
    )

    op.create_table(
        'attack_chains',
        sa.Column('scan_run_id', sa.Uuid(), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('severity', sa.String(length=16), nullable=False),
        sa.Column('finding_ids', sa.JSON(), nullable=False),
        sa.Column('plain_language_summary', sa.Text(), nullable=False),
        sa.Column('narrative', sa.Text(), nullable=False),
        sa.Column('steps_to_reproduce', sa.JSON(), nullable=False),
        sa.Column('references', sa.JSON(), nullable=False),
        sa.Column('confirmation_status', sa.String(length=20), nullable=False),
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['scan_run_id'], ['scan_runs.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_table(
        'attack_chain_evidence',
        sa.Column('attack_chain_id', sa.Uuid(), nullable=False),
        sa.Column('request_raw', sa.Text(), nullable=False),
        sa.Column('response_raw', sa.Text(), nullable=False),
        sa.Column('screenshot_refs', sa.JSON(), nullable=False),
        sa.Column('additional_notes', sa.Text(), nullable=True),
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['attack_chain_id'], ['attack_chains.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )

    _seed_user_permissions()


def downgrade() -> None:
    role_permissions = sa.table("role_permissions", sa.column("resource", sa.String()))
    op.execute(role_permissions.delete().where(role_permissions.c.resource == "user"))

    op.drop_table('attack_chain_evidence')
    op.drop_table('attack_chains')

    op.drop_column('users', 'invite_accepted_at')
    op.drop_column('users', 'invited_at')
    op.drop_index('ix_users_invite_token', table_name='users')
    op.drop_constraint('uq_users_invite_token', 'users', type_='unique')
    op.drop_column('users', 'invite_token')

    op.drop_column('projects', 'archived_at')

    op.drop_column('vgs_configs', 'masked_auth_reference')
    op.drop_column('vgs_configs', 'encrypted_auth_value')
    op.drop_column('vgs_configs', 'auth_type')

    op.drop_column('notification_configs', 'encrypted_config_json')
    op.alter_column('notification_configs', 'encrypted_webhook_url', nullable=False)

    op.drop_column('ai_provider_configs', 'auth_type')
