"""add_blue_guardian_threat_detections

Revision ID: b7d82f3a9e10
Revises: 98e43473dce2
Create Date: 2026-11-01 02:40:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'b7d82f3a9e10'
down_revision: Union[str, Sequence[str], None] = '98e43473dce2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add threat_detections_count column to guardian_executions
    op.add_column(
        'guardian_executions',
        sa.Column('threat_detections_count', sa.Integer(), server_default='0', nullable=False),
    )

    # 2. Create threat_detections table
    op.create_table(
        'threat_detections',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('guardian_execution_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('correlated_group_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('sandbox_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('detection_code', sa.String(length=64), nullable=False),
        sa.Column('rule_code', sa.String(length=64), nullable=False),
        sa.Column('rule_version', sa.String(length=16), server_default='1.0.0', nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('classification', sa.String(length=64), nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=False),
        sa.Column('confidence_score', sa.Float(), nullable=False),
        sa.Column('mitre_techniques', postgresql.JSONB(astext_type=sa.Text()), server_default='[]', nullable=False),
        sa.Column('mitre_tactics', postgresql.JSONB(astext_type=sa.Text()), server_default='[]', nullable=False),
        sa.Column('affected_asset_ids', postgresql.JSONB(astext_type=sa.Text()), server_default='[]', nullable=False),
        sa.Column('evidence_references', postgresql.JSONB(astext_type=sa.Text()), server_default='{}', nullable=False),
        sa.Column('detection_rationale', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=32), server_default='new', nullable=False),
        sa.Column('is_simulated', sa.Boolean(), server_default='true', nullable=False),
        sa.Column('simulation_only', sa.Boolean(), server_default='true', nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ['guardian_execution_id'],
            ['guardian_executions.id'],
            name='fk_threat_detections_guardian_execution_id',
            ondelete='RESTRICT',
        ),
        sa.ForeignKeyConstraint(
            ['correlated_group_id'],
            ['correlated_event_groups.id'],
            name='fk_threat_detections_correlated_group_id',
            ondelete='RESTRICT',
        ),
        sa.ForeignKeyConstraint(
            ['sandbox_id'],
            ['sandbox_environments.id'],
            name='fk_threat_detections_sandbox_id',
            ondelete='RESTRICT',
        ),
        sa.UniqueConstraint(
            'guardian_execution_id',
            'rule_code',
            'correlated_group_id',
            name='uq_threat_detection_exec_rule_group',
        ),
    )

    # 3. Create Indexes
    op.create_index('ix_threat_detections_guardian_execution_id', 'threat_detections', ['guardian_execution_id'])
    op.create_index('ix_threat_detections_correlated_group_id', 'threat_detections', ['correlated_group_id'])
    op.create_index('ix_threat_detections_sandbox_id', 'threat_detections', ['sandbox_id'])
    op.create_index('ix_threat_detections_detection_code', 'threat_detections', ['detection_code'])
    op.create_index('ix_threat_detections_rule_code', 'threat_detections', ['rule_code'])
    op.create_index('ix_threat_detections_classification', 'threat_detections', ['classification'])
    op.create_index('ix_threat_detections_severity', 'threat_detections', ['severity'])
    op.create_index('ix_threat_detections_status', 'threat_detections', ['status'])
    op.create_index('ix_threat_detections_sandbox_severity', 'threat_detections', ['sandbox_id', 'severity'])
    op.create_index('ix_threat_detections_sandbox_classification', 'threat_detections', ['sandbox_id', 'classification'])


def downgrade() -> None:
    op.drop_index('ix_threat_detections_sandbox_classification', table_name='threat_detections')
    op.drop_index('ix_threat_detections_sandbox_severity', table_name='threat_detections')
    op.drop_index('ix_threat_detections_status', table_name='threat_detections')
    op.drop_index('ix_threat_detections_severity', table_name='threat_detections')
    op.drop_index('ix_threat_detections_classification', table_name='threat_detections')
    op.drop_index('ix_threat_detections_rule_code', table_name='threat_detections')
    op.drop_index('ix_threat_detections_detection_code', table_name='threat_detections')
    op.drop_index('ix_threat_detections_sandbox_id', table_name='threat_detections')
    op.drop_index('ix_threat_detections_correlated_group_id', table_name='threat_detections')
    op.drop_index('ix_threat_detections_guardian_execution_id', table_name='threat_detections')
    op.drop_table('threat_detections')
    op.drop_column('guardian_executions', 'threat_detections_count')

