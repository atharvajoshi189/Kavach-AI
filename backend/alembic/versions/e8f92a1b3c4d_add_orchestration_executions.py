"""add orchestration_executions table for unified lifecycle

Revision ID: e8f92a1b3c4d
Revises: c370819fe24b
Create Date: 2026-11-01 05:12:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'e8f92a1b3c4d'
down_revision: Union[str, None] = 'c370819fe24b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'orchestration_executions',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('sandbox_id', sa.UUID(), nullable=False),
        sa.Column('campaign_id', sa.UUID(), nullable=True),
        sa.Column('simulation_id', sa.UUID(), nullable=True),
        sa.Column('attack_path_id', sa.UUID(), nullable=True),
        sa.Column('guardian_execution_id', sa.UUID(), nullable=True),
        sa.Column('remediation_plan_id', sa.UUID(), nullable=True),
        sa.Column('approval_request_id', sa.UUID(), nullable=True),
        sa.Column('synthetic_execution_id', sa.UUID(), nullable=True),
        sa.Column('verification_id', sa.UUID(), nullable=True),
        sa.Column('current_stage', sa.String(length=64), nullable=False),
        sa.Column('execution_status', sa.String(length=32), nullable=False),
        sa.Column('failed_stage', sa.String(length=64), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('retry_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('is_resumable', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('stage_metrics', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('execution_metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['approval_request_id'], ['guardian_approval_requests.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['attack_path_id'], ['attack_paths.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['campaign_id'], ['campaigns.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['guardian_execution_id'], ['guardian_executions.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['remediation_plan_id'], ['remediation_plans.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['sandbox_id'], ['sandbox_environments.id'], ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['simulation_id'], ['attack_runs.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['synthetic_execution_id'], ['synthetic_remediation_executions.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['verification_id'], ['remediation_verifications.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_orchestration_executions_approval_request_id'), 'orchestration_executions', ['approval_request_id'], unique=False)
    op.create_index(op.f('ix_orchestration_executions_attack_path_id'), 'orchestration_executions', ['attack_path_id'], unique=False)
    op.create_index(op.f('ix_orchestration_executions_campaign_id'), 'orchestration_executions', ['campaign_id'], unique=False)
    op.create_index(op.f('ix_orchestration_executions_current_stage'), 'orchestration_executions', ['current_stage'], unique=False)
    op.create_index(op.f('ix_orchestration_executions_execution_status'), 'orchestration_executions', ['execution_status'], unique=False)
    op.create_index(op.f('ix_orchestration_executions_guardian_execution_id'), 'orchestration_executions', ['guardian_execution_id'], unique=False)
    op.create_index(op.f('ix_orchestration_executions_remediation_plan_id'), 'orchestration_executions', ['remediation_plan_id'], unique=False)
    op.create_index(op.f('ix_orchestration_executions_sandbox_id'), 'orchestration_executions', ['sandbox_id'], unique=False)
    op.create_index(op.f('ix_orchestration_executions_simulation_id'), 'orchestration_executions', ['simulation_id'], unique=False)
    op.create_index(op.f('ix_orchestration_executions_synthetic_execution_id'), 'orchestration_executions', ['synthetic_execution_id'], unique=False)
    op.create_index(op.f('ix_orchestration_executions_verification_id'), 'orchestration_executions', ['verification_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_orchestration_executions_verification_id'), table_name='orchestration_executions')
    op.drop_index(op.f('ix_orchestration_executions_synthetic_execution_id'), table_name='orchestration_executions')
    op.drop_index(op.f('ix_orchestration_executions_simulation_id'), table_name='orchestration_executions')
    op.drop_index(op.f('ix_orchestration_executions_sandbox_id'), table_name='orchestration_executions')
    op.drop_index(op.f('ix_orchestration_executions_remediation_plan_id'), table_name='orchestration_executions')
    op.drop_index(op.f('ix_orchestration_executions_guardian_execution_id'), table_name='orchestration_executions')
    op.drop_index(op.f('ix_orchestration_executions_execution_status'), table_name='orchestration_executions')
    op.drop_index(op.f('ix_orchestration_executions_current_stage'), table_name='orchestration_executions')
    op.drop_index(op.f('ix_orchestration_executions_campaign_id'), table_name='orchestration_executions')
    op.drop_index(op.f('ix_orchestration_executions_attack_path_id'), table_name='orchestration_executions')
    op.drop_index(op.f('ix_orchestration_executions_approval_request_id'), table_name='orchestration_executions')
    op.drop_table('orchestration_executions')

