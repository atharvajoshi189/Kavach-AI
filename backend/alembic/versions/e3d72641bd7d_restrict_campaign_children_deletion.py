"""restrict_campaign_children_deletion

Revision ID: e3d72641bd7d
Revises: f7e3be01282d
Create Date: 2026-10-31 21:05:50.619821

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e3d72641bd7d'
down_revision: Union[str, Sequence[str], None] = 'f7e3be01282d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema to restrict campaign deletion when attack runs or evaluations exist."""
    op.drop_constraint('attack_runs_campaign_id_fkey', 'attack_runs', type_='foreignkey')
    op.create_foreign_key(
        'attack_runs_campaign_id_fkey',
        'attack_runs',
        'campaigns',
        ['campaign_id'],
        ['id'],
        ondelete='RESTRICT',
    )
    op.drop_constraint('evaluations_campaign_id_fkey', 'evaluations', type_='foreignkey')
    op.create_foreign_key(
        'evaluations_campaign_id_fkey',
        'evaluations',
        'campaigns',
        ['campaign_id'],
        ['id'],
        ondelete='RESTRICT',
    )


def downgrade() -> None:
    """Downgrade schema to cascade delete attack runs and evaluations."""
    op.drop_constraint('evaluations_campaign_id_fkey', 'evaluations', type_='foreignkey')
    op.create_foreign_key(
        'evaluations_campaign_id_fkey',
        'evaluations',
        'campaigns',
        ['campaign_id'],
        ['id'],
        ondelete='CASCADE',
    )
    op.drop_constraint('attack_runs_campaign_id_fkey', 'attack_runs', type_='foreignkey')
    op.create_foreign_key(
        'attack_runs_campaign_id_fkey',
        'attack_runs',
        'campaigns',
        ['campaign_id'],
        ['id'],
        ondelete='CASCADE',
    )
