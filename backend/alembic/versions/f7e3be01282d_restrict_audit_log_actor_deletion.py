"""restrict_audit_log_actor_deletion

Revision ID: f7e3be01282d
Revises: 004152a0801a
Create Date: 2026-10-31 20:00:24.126101

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f7e3be01282d'
down_revision: Union[str, Sequence[str], None] = '004152a0801a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema to restrict user deletion when audit logs reference the user."""
    op.drop_constraint('audit_logs_actor_id_fkey', 'audit_logs', type_='foreignkey')
    op.create_foreign_key(
        'audit_logs_actor_id_fkey',
        'audit_logs',
        'users',
        ['actor_id'],
        ['id'],
        ondelete='RESTRICT',
    )


def downgrade() -> None:
    """Downgrade schema to allow nullification on user deletion."""
    op.drop_constraint('audit_logs_actor_id_fkey', 'audit_logs', type_='foreignkey')
    op.create_foreign_key(
        'audit_logs_actor_id_fkey',
        'audit_logs',
        'users',
        ['actor_id'],
        ['id'],
        ondelete='SET NULL',
    )
