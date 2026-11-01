"""add_blue_guardian_risk_analysis_and_asset_impact

Revision ID: c8e91a2b3c4d
Revises: b7d82f3a9e10
Create Date: 2026-11-01 02:55:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'c8e91a2b3c4d'
down_revision: Union[str, Sequence[str], None] = 'b7d82f3a9e10'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add risk_assessments_count and max_risk_score to guardian_executions
    op.add_column(
        'guardian_executions',
        sa.Column('risk_assessments_count', sa.Integer(), server_default='0', nullable=False),
    )
    op.add_column(
        'guardian_executions',
        sa.Column('max_risk_score', sa.Float(), server_default='0.0', nullable=False),
    )

    # 2. Create threat_risk_assessments table
    op.create_table(
        'threat_risk_assessments',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('threat_detection_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('guardian_execution_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('sandbox_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('risk_score', sa.Float(), nullable=False),
        sa.Column('risk_category', sa.String(length=32), nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=False),
        sa.Column('asset_criticality_score', sa.Float(), nullable=False),
        sa.Column('direct_impact_score', sa.Float(), nullable=False),
        sa.Column('blast_radius_score', sa.Float(), nullable=False),
        sa.Column('attack_stage_score', sa.Float(), nullable=False),
        sa.Column('evidence_confidence_score', sa.Float(), nullable=False),
        sa.Column('scoring_formula_version', sa.String(length=32), server_default='1.0.0', nullable=False),
        sa.Column('assessment_rationale', sa.Text(), nullable=False),
        sa.Column('assessment_status', sa.String(length=32), server_default='completed', nullable=False),
        sa.Column('assessed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('is_simulated', sa.Boolean(), server_default='true', nullable=False),
        sa.Column('simulation_only', sa.Boolean(), server_default='true', nullable=False),
        sa.ForeignKeyConstraint(
            ['threat_detection_id'],
            ['threat_detections.id'],
            name='fk_threat_risk_assessments_threat_detection_id',
            ondelete='RESTRICT',
        ),
        sa.ForeignKeyConstraint(
            ['guardian_execution_id'],
            ['guardian_executions.id'],
            name='fk_threat_risk_assessments_guardian_execution_id',
            ondelete='RESTRICT',
        ),
        sa.ForeignKeyConstraint(
            ['sandbox_id'],
            ['sandbox_environments.id'],
            name='fk_threat_risk_assessments_sandbox_id',
            ondelete='RESTRICT',
        ),
        sa.UniqueConstraint(
            'guardian_execution_id',
            'threat_detection_id',
            name='uq_risk_assessment_exec_detection',
        ),
    )

    op.create_index('ix_threat_risk_assessments_threat_detection_id', 'threat_risk_assessments', ['threat_detection_id'])
    op.create_index('ix_threat_risk_assessments_guardian_execution_id', 'threat_risk_assessments', ['guardian_execution_id'])
    op.create_index('ix_threat_risk_assessments_sandbox_id', 'threat_risk_assessments', ['sandbox_id'])
    op.create_index('ix_threat_risk_assessments_risk_score', 'threat_risk_assessments', ['risk_score'])
    op.create_index('ix_threat_risk_assessments_risk_category', 'threat_risk_assessments', ['risk_category'])
    op.create_index('ix_threat_risk_assessments_severity', 'threat_risk_assessments', ['severity'])
    op.create_index('ix_threat_risk_assessments_status', 'threat_risk_assessments', ['assessment_status'])
    op.create_index('ix_threat_risk_assessments_sandbox_category', 'threat_risk_assessments', ['sandbox_id', 'risk_category'])
    op.create_index('ix_threat_risk_assessments_sandbox_score', 'threat_risk_assessments', ['sandbox_id', 'risk_score'])

    # 3. Create threat_asset_impacts table
    op.create_table(
        'threat_asset_impacts',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('risk_assessment_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('asset_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('sandbox_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('impact_type', sa.String(length=32), nullable=False),
        sa.Column('impact_score', sa.Float(), nullable=False),
        sa.Column('traversal_depth', sa.Integer(), server_default='0', nullable=False),
        sa.Column('relationship_path', postgresql.JSONB(astext_type=sa.Text()), server_default='[]', nullable=False),
        sa.Column('impact_rationale', sa.Text(), nullable=False),
        sa.Column('evidence_references', postgresql.JSONB(astext_type=sa.Text()), server_default='{}', nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ['risk_assessment_id'],
            ['threat_risk_assessments.id'],
            name='fk_threat_asset_impacts_risk_assessment_id',
            ondelete='RESTRICT',
        ),
        sa.ForeignKeyConstraint(
            ['asset_id'],
            ['synthetic_assets.id'],
            name='fk_threat_asset_impacts_asset_id',
            ondelete='RESTRICT',
        ),
        sa.ForeignKeyConstraint(
            ['sandbox_id'],
            ['sandbox_environments.id'],
            name='fk_threat_asset_impacts_sandbox_id',
            ondelete='RESTRICT',
        ),
        sa.UniqueConstraint(
            'risk_assessment_id',
            'asset_id',
            name='uq_asset_impact_assessment_asset',
        ),
    )

    op.create_index('ix_threat_asset_impacts_risk_assessment_id', 'threat_asset_impacts', ['risk_assessment_id'])
    op.create_index('ix_threat_asset_impacts_asset_id', 'threat_asset_impacts', ['asset_id'])
    op.create_index('ix_threat_asset_impacts_sandbox_id', 'threat_asset_impacts', ['sandbox_id'])
    op.create_index('ix_threat_asset_impacts_impact_type', 'threat_asset_impacts', ['impact_type'])
    op.create_index('ix_threat_asset_impacts_sandbox_type', 'threat_asset_impacts', ['sandbox_id', 'impact_type'])


def downgrade() -> None:
    op.drop_index('ix_threat_asset_impacts_sandbox_type', table_name='threat_asset_impacts')
    op.drop_index('ix_threat_asset_impacts_impact_type', table_name='threat_asset_impacts')
    op.drop_index('ix_threat_asset_impacts_sandbox_id', table_name='threat_asset_impacts')
    op.drop_index('ix_threat_asset_impacts_asset_id', table_name='threat_asset_impacts')
    op.drop_index('ix_threat_asset_impacts_risk_assessment_id', table_name='threat_asset_impacts')
    op.drop_table('threat_asset_impacts')

    op.drop_index('ix_threat_risk_assessments_sandbox_score', table_name='threat_risk_assessments')
    op.drop_index('ix_threat_risk_assessments_sandbox_category', table_name='threat_risk_assessments')
    op.drop_index('ix_threat_risk_assessments_status', table_name='threat_risk_assessments')
    op.drop_index('ix_threat_risk_assessments_severity', table_name='threat_risk_assessments')
    op.drop_index('ix_threat_risk_assessments_risk_category', table_name='threat_risk_assessments')
    op.drop_index('ix_threat_risk_assessments_risk_score', table_name='threat_risk_assessments')
    op.drop_index('ix_threat_risk_assessments_sandbox_id', table_name='threat_risk_assessments')
    op.drop_index('ix_threat_risk_assessments_guardian_execution_id', table_name='threat_risk_assessments')
    op.drop_index('ix_threat_risk_assessments_threat_detection_id', table_name='threat_risk_assessments')
    op.drop_table('threat_risk_assessments')

    op.drop_column('guardian_executions', 'max_risk_score')
    op.drop_column('guardian_executions', 'risk_assessments_count')

