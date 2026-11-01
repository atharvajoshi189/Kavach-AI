"""restrict_guardian_execution_children_deletion

Revision ID: 98e43473dce2
Revises: 05cafdffa764
Create Date: 2026-11-01 02:26:28.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '98e43473dce2'
down_revision: Union[str, Sequence[str], None] = '05cafdffa764'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema to restrict guardian execution deletion when defensive events or correlated groups exist."""
    op.drop_constraint('defensive_event_records_guardian_execution_id_fkey', 'defensive_event_records', type_='foreignkey')
    op.create_foreign_key(
        'defensive_event_records_guardian_execution_id_fkey',
        'defensive_event_records',
        'guardian_executions',
        ['guardian_execution_id'],
        ['id'],
        ondelete='RESTRICT',
    )
    op.drop_constraint('correlated_event_groups_guardian_execution_id_fkey', 'correlated_event_groups', type_='foreignkey')
    op.create_foreign_key(
        'correlated_event_groups_guardian_execution_id_fkey',
        'correlated_event_groups',
        'guardian_executions',
        ['guardian_execution_id'],
        ['id'],
        ondelete='RESTRICT',
    )


def downgrade() -> None:
    """Downgrade schema to cascade delete defensive events and correlated groups."""
    op.drop_constraint('correlated_event_groups_guardian_execution_id_fkey', 'correlated_event_groups', type_='foreignkey')
    op.create_foreign_key(
        'correlated_event_groups_guardian_execution_id_fkey',
        'correlated_event_groups',
        'guardian_executions',
        ['guardian_execution_id'],
        ['id'],
        ondelete='CASCADE',
    )
    op.drop_constraint('defensive_event_records_guardian_execution_id_fkey', 'defensive_event_records', type_='foreignkey')
    op.create_foreign_key(
        'defensive_event_records_guardian_execution_id_fkey',
        'defensive_event_records',
        'guardian_executions',
        ['guardian_execution_id'],
        ['id'],
        ondelete='CASCADE',
    )
