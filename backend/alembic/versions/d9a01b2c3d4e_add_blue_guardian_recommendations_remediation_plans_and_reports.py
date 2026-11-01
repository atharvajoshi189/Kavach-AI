"""Add Blue Guardian recommendations, remediation planning, and incident reports.

Revision ID: d9a01b2c3d4e
Revises: c8e91a2b3c4d
Create Date: 2026-11-01 03:22:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = 'd9a01b2c3d4e'
down_revision = 'c8e91a2b3c4d'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Alter guardian_executions to add count metrics
    op.add_column(
        'guardian_executions',
        sa.Column('recommendations_count', sa.Integer(), server_default='0', nullable=False),
    )
    op.add_column(
        'guardian_executions',
        sa.Column('remediation_plans_count', sa.Integer(), server_default='0', nullable=False),
    )
    op.add_column(
        'guardian_executions',
        sa.Column('incident_reports_count', sa.Integer(), server_default='0', nullable=False),
    )

    # 2. Create defensive_recommendations table
    op.create_table(
        'defensive_recommendations',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('guardian_execution_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('threat_detection_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('risk_assessment_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('sandbox_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('recommendation_code', sa.String(length=64), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('priority', sa.String(length=16), nullable=False),  # P0, P1, P2, P3
        sa.Column('recommendation_type', sa.String(length=64), nullable=False),  # preventive, detective, corrective, compensating
        sa.Column('playbook_id', sa.String(length=64), nullable=False),
        sa.Column('playbook_version', sa.String(length=16), server_default='1.0.0', nullable=False),
        sa.Column('affected_asset_ids', postgresql.JSONB(astext_type=sa.Text()), server_default='[]', nullable=False),
        sa.Column('evidence_references', postgresql.JSONB(astext_type=sa.Text()), server_default='{}', nullable=False),
        sa.Column('rationale', sa.Text(), nullable=False),
        sa.Column('expected_outcome', sa.Text(), nullable=False),
        sa.Column('verification_criteria', postgresql.JSONB(astext_type=sa.Text()), server_default='[]', nullable=False),
        sa.Column('implementation_complexity', sa.String(length=32), server_default='medium', nullable=False),
        sa.Column('status', sa.String(length=32), server_default='proposed', nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('is_simulated', sa.Boolean(), server_default='true', nullable=False),
        sa.Column('simulation_only', sa.Boolean(), server_default='true', nullable=False),
        sa.ForeignKeyConstraint(
            ['guardian_execution_id'],
            ['guardian_executions.id'],
            name='fk_defensive_recommendations_guardian_execution_id',
            ondelete='RESTRICT',
        ),
        sa.ForeignKeyConstraint(
            ['threat_detection_id'],
            ['threat_detections.id'],
            name='fk_defensive_recommendations_threat_detection_id',
            ondelete='RESTRICT',
        ),
        sa.ForeignKeyConstraint(
            ['risk_assessment_id'],
            ['threat_risk_assessments.id'],
            name='fk_defensive_recommendations_risk_assessment_id',
            ondelete='RESTRICT',
        ),
        sa.ForeignKeyConstraint(
            ['sandbox_id'],
            ['sandbox_environments.id'],
            name='fk_defensive_recommendations_sandbox_id',
            ondelete='RESTRICT',
        ),
        sa.UniqueConstraint(
            'guardian_execution_id',
            'threat_detection_id',
            'playbook_id',
            name='uq_defensive_rec_exec_det_playbook',
        ),
    )

    op.create_index('ix_defensive_recommendations_exec_id', 'defensive_recommendations', ['guardian_execution_id'])
    op.create_index('ix_defensive_recommendations_det_id', 'defensive_recommendations', ['threat_detection_id'])
    op.create_index('ix_defensive_recommendations_risk_id', 'defensive_recommendations', ['risk_assessment_id'])
    op.create_index('ix_defensive_recommendations_sandbox_id', 'defensive_recommendations', ['sandbox_id'])
    op.create_index('ix_defensive_recommendations_code', 'defensive_recommendations', ['recommendation_code'])
    op.create_index('ix_defensive_recommendations_priority', 'defensive_recommendations', ['priority'])
    op.create_index('ix_defensive_recommendations_type', 'defensive_recommendations', ['recommendation_type'])
    op.create_index('ix_defensive_recommendations_playbook', 'defensive_recommendations', ['playbook_id'])
    op.create_index('ix_defensive_recommendations_status', 'defensive_recommendations', ['status'])

    # 3. Create remediation_plans table
    op.create_table(
        'remediation_plans',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('guardian_execution_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('sandbox_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('overall_priority', sa.String(length=16), nullable=False),  # P0, P1, P2, P3
        sa.Column('status', sa.String(length=32), server_default='draft', nullable=False),  # draft, approved, rejected, executed
        sa.Column('plan_version', sa.String(length=16), server_default='1.0.0', nullable=False),
        sa.Column('target_asset_ids', postgresql.JSONB(astext_type=sa.Text()), server_default='[]', nullable=False),
        sa.Column('plan_metadata', postgresql.JSONB(astext_type=sa.Text()), server_default='{}', nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('is_simulated', sa.Boolean(), server_default='true', nullable=False),
        sa.Column('simulation_only', sa.Boolean(), server_default='true', nullable=False),
        sa.ForeignKeyConstraint(
            ['guardian_execution_id'],
            ['guardian_executions.id'],
            name='fk_remediation_plans_guardian_execution_id',
            ondelete='RESTRICT',
        ),
        sa.ForeignKeyConstraint(
            ['sandbox_id'],
            ['sandbox_environments.id'],
            name='fk_remediation_plans_sandbox_id',
            ondelete='RESTRICT',
        ),
    )

    op.create_index('ix_remediation_plans_exec_id', 'remediation_plans', ['guardian_execution_id'])
    op.create_index('ix_remediation_plans_sandbox_id', 'remediation_plans', ['sandbox_id'])
    op.create_index('ix_remediation_plans_priority', 'remediation_plans', ['overall_priority'])
    op.create_index('ix_remediation_plans_status', 'remediation_plans', ['status'])

    # 4. Create remediation_plan_actions table
    op.create_table(
        'remediation_plan_actions',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('remediation_plan_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('recommendation_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('action_code', sa.String(length=64), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('sequence_order', sa.Integer(), server_default='1', nullable=False),
        sa.Column('priority', sa.String(length=16), nullable=False),
        sa.Column('depends_on', postgresql.JSONB(astext_type=sa.Text()), server_default='[]', nullable=False),
        sa.Column('target_asset_ids', postgresql.JSONB(astext_type=sa.Text()), server_default='[]', nullable=False),
        sa.Column('expected_outcome', sa.Text(), nullable=False),
        sa.Column('verification_criteria', postgresql.JSONB(astext_type=sa.Text()), server_default='[]', nullable=False),
        sa.Column('action_type', sa.String(length=64), nullable=False),
        sa.Column('status', sa.String(length=32), server_default='pending', nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ['remediation_plan_id'],
            ['remediation_plans.id'],
            name='fk_remediation_plan_actions_plan_id',
            ondelete='CASCADE',
        ),
        sa.ForeignKeyConstraint(
            ['recommendation_id'],
            ['defensive_recommendations.id'],
            name='fk_remediation_plan_actions_recommendation_id',
            ondelete='RESTRICT',
        ),
    )

    op.create_index('ix_remediation_plan_actions_plan_id', 'remediation_plan_actions', ['remediation_plan_id'])
    op.create_index('ix_remediation_plan_actions_rec_id', 'remediation_plan_actions', ['recommendation_id'])
    op.create_index('ix_remediation_plan_actions_code', 'remediation_plan_actions', ['action_code'])
    op.create_index('ix_remediation_plan_actions_seq', 'remediation_plan_actions', ['sequence_order'])

    # 5. Create incident_reports table
    op.create_table(
        'incident_reports',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('guardian_execution_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('sandbox_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('report_version', sa.Integer(), server_default='1', nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('executive_summary', sa.Text(), nullable=False),
        sa.Column('threat_classifications', postgresql.JSONB(astext_type=sa.Text()), server_default='[]', nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=False),
        sa.Column('max_risk_score', sa.Float(), nullable=False),
        sa.Column('risk_category', sa.String(length=32), nullable=False),
        sa.Column('affected_asset_ids', postgresql.JSONB(astext_type=sa.Text()), server_default='[]', nullable=False),
        sa.Column('potentially_exposed_asset_ids', postgresql.JSONB(astext_type=sa.Text()), server_default='[]', nullable=False),
        sa.Column('blast_radius_nodes_count', sa.Integer(), server_default='0', nullable=False),
        sa.Column('mitre_techniques', postgresql.JSONB(astext_type=sa.Text()), server_default='[]', nullable=False),
        sa.Column('event_timeline', postgresql.JSONB(astext_type=sa.Text()), server_default='[]', nullable=False),
        sa.Column('detection_summaries', postgresql.JSONB(astext_type=sa.Text()), server_default='[]', nullable=False),
        sa.Column('recommendation_summaries', postgresql.JSONB(astext_type=sa.Text()), server_default='[]', nullable=False),
        sa.Column('remediation_plan_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('report_content', postgresql.JSONB(astext_type=sa.Text()), server_default='{}', nullable=False),
        sa.Column('report_status', sa.String(length=32), server_default='published', nullable=False),
        sa.Column('generated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ['guardian_execution_id'],
            ['guardian_executions.id'],
            name='fk_incident_reports_guardian_execution_id',
            ondelete='RESTRICT',
        ),
        sa.ForeignKeyConstraint(
            ['sandbox_id'],
            ['sandbox_environments.id'],
            name='fk_incident_reports_sandbox_id',
            ondelete='RESTRICT',
        ),
        sa.ForeignKeyConstraint(
            ['remediation_plan_id'],
            ['remediation_plans.id'],
            name='fk_incident_reports_remediation_plan_id',
            ondelete='SET NULL',
        ),
        sa.UniqueConstraint(
            'guardian_execution_id',
            'report_version',
            name='uq_incident_report_exec_version',
        ),
    )

    op.create_index('ix_incident_reports_exec_id', 'incident_reports', ['guardian_execution_id'])
    op.create_index('ix_incident_reports_sandbox_id', 'incident_reports', ['sandbox_id'])
    op.create_index('ix_incident_reports_version', 'incident_reports', ['report_version'])
    op.create_index('ix_incident_reports_status', 'incident_reports', ['report_status'])


def downgrade() -> None:
    op.drop_index('ix_incident_reports_status', table_name='incident_reports')
    op.drop_index('ix_incident_reports_version', table_name='incident_reports')
    op.drop_index('ix_incident_reports_sandbox_id', table_name='incident_reports')
    op.drop_index('ix_incident_reports_exec_id', table_name='incident_reports')
    op.drop_table('incident_reports')

    op.drop_index('ix_remediation_plan_actions_seq', table_name='remediation_plan_actions')
    op.drop_index('ix_remediation_plan_actions_code', table_name='remediation_plan_actions')
    op.drop_index('ix_remediation_plan_actions_rec_id', table_name='remediation_plan_actions')
    op.drop_index('ix_remediation_plan_actions_plan_id', table_name='remediation_plan_actions')
    op.drop_table('remediation_plan_actions')

    op.drop_index('ix_remediation_plans_status', table_name='remediation_plans')
    op.drop_index('ix_remediation_plans_priority', table_name='remediation_plans')
    op.drop_index('ix_remediation_plans_sandbox_id', table_name='remediation_plans')
    op.drop_index('ix_remediation_plans_exec_id', table_name='remediation_plans')
    op.drop_table('remediation_plans')

    op.drop_index('ix_defensive_recommendations_status', table_name='defensive_recommendations')
    op.drop_index('ix_defensive_recommendations_playbook', table_name='defensive_recommendations')
    op.drop_index('ix_defensive_recommendations_type', table_name='defensive_recommendations')
    op.drop_index('ix_defensive_recommendations_priority', table_name='defensive_recommendations')
    op.drop_index('ix_defensive_recommendations_code', table_name='defensive_recommendations')
    op.drop_index('ix_defensive_recommendations_sandbox_id', table_name='defensive_recommendations')
    op.drop_index('ix_defensive_recommendations_risk_id', table_name='defensive_recommendations')
    op.drop_index('ix_defensive_recommendations_det_id', table_name='defensive_recommendations')
    op.drop_index('ix_defensive_recommendations_exec_id', table_name='defensive_recommendations')
    op.drop_table('defensive_recommendations')

    op.drop_column('guardian_executions', 'incident_reports_count')
    op.drop_column('guardian_executions', 'remediation_plans_count')
    op.drop_column('guardian_executions', 'recommendations_count')

