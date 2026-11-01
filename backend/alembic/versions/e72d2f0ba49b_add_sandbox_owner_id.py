"""add_sandbox_owner_id

Revision ID: e72d2f0ba49b
Revises: e3068c97d9ec
Create Date: 2026-10-31 22:31:01.341120

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e72d2f0ba49b'
down_revision: Union[str, Sequence[str], None] = 'e3068c97d9ec'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('sandbox_environments', sa.Column('owner_id', sa.UUID(), nullable=True))
    op.create_index(op.f('ix_sandbox_environments_owner_id'), 'sandbox_environments', ['owner_id'], unique=False)
    op.create_foreign_key(
        'fk_sandbox_environments_owner_id_users',
        'sandbox_environments',
        'users',
        ['owner_id'],
        ['id'],
        ondelete='SET NULL',
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_constraint('fk_sandbox_environments_owner_id_users', 'sandbox_environments', type_='foreignkey')
    op.drop_index(op.f('ix_sandbox_environments_owner_id'), table_name='sandbox_environments')
    op.drop_column('sandbox_environments', 'owner_id')
