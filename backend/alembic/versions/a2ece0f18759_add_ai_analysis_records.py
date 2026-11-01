"""add_ai_analysis_records

Revision ID: a2ece0f18759
Revises: e8f92a1b3c4d
Create Date: 2026-11-01 06:51:52.497925

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'a2ece0f18759'
down_revision: Union[str, Sequence[str], None] = 'e8f92a1b3c4d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema: create ai_analysis_records table."""
    op.create_table(
        'ai_analysis_records',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('sandbox_id', sa.UUID(), nullable=False),
        sa.Column('guardian_execution_id', sa.UUID(), nullable=True),
        sa.Column('analysis_type', sa.String(length=64), nullable=False),
        sa.Column('source_entity_type', sa.String(length=64), nullable=False),
        sa.Column('source_entity_id', sa.UUID(), nullable=False),
        sa.Column('source_version', sa.String(length=64), nullable=True),
        sa.Column('provider', sa.String(length=32), nullable=False),
        sa.Column('model', sa.String(length=64), nullable=False),
        sa.Column('prompt_version', sa.String(length=32), nullable=False),
        sa.Column('response_content', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('evidence_references', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('fallback_used', sa.Boolean(), nullable=False),
        sa.Column('fallback_reason', sa.Text(), nullable=True),
        sa.Column('tokens_used', sa.Integer(), nullable=True),
        sa.Column('latency_ms', sa.Float(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_by', sa.UUID(), nullable=True),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['guardian_execution_id'], ['guardian_executions.id'], ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['sandbox_id'], ['sandbox_environments.id'], ondelete='RESTRICT'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_ai_analysis_records_analysis_type'), 'ai_analysis_records', ['analysis_type'], unique=False)
    op.create_index(op.f('ix_ai_analysis_records_guardian_execution_id'), 'ai_analysis_records', ['guardian_execution_id'], unique=False)
    op.create_index(op.f('ix_ai_analysis_records_sandbox_id'), 'ai_analysis_records', ['sandbox_id'], unique=False)
    op.create_index(op.f('ix_ai_analysis_records_source_entity_id'), 'ai_analysis_records', ['source_entity_id'], unique=False)
    op.create_index(op.f('ix_ai_analysis_records_source_entity_type'), 'ai_analysis_records', ['source_entity_type'], unique=False)
    op.create_index('ix_ai_analysis_sandbox_type', 'ai_analysis_records', ['sandbox_id', 'analysis_type'], unique=False)
    op.create_index('ix_ai_analysis_source', 'ai_analysis_records', ['source_entity_id', 'analysis_type'], unique=False)


def downgrade() -> None:
    """Downgrade schema: drop ai_analysis_records table."""
    op.drop_index('ix_ai_analysis_source', table_name='ai_analysis_records')
    op.drop_index('ix_ai_analysis_sandbox_type', table_name='ai_analysis_records')
    op.drop_index(op.f('ix_ai_analysis_records_source_entity_type'), table_name='ai_analysis_records')
    op.drop_index(op.f('ix_ai_analysis_records_source_entity_id'), table_name='ai_analysis_records')
    op.drop_index(op.f('ix_ai_analysis_records_sandbox_id'), table_name='ai_analysis_records')
    op.drop_index(op.f('ix_ai_analysis_records_guardian_execution_id'), table_name='ai_analysis_records')
    op.drop_index(op.f('ix_ai_analysis_records_analysis_type'), table_name='ai_analysis_records')
    op.drop_table('ai_analysis_records')
