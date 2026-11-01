"""Data access and management service for Autonomous Agents."""

from typing import Any, Optional
import uuid
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.agent import Agent


async def create_agent(
    session: AsyncSession,
    name: str,
    agent_type: str,
    description: Optional[str] = None,
    capabilities: Optional[dict[str, Any]] = None,
    status: str = "idle",
    environment: str = "sandbox",
) -> Agent:
    """Creates and persists an Agent entity."""
    agent = Agent(
        name=name,
        agent_type=agent_type,
        description=description,
        capabilities=capabilities or {},
        status=status,
        environment=environment,
    )
    session.add(agent)
    await session.flush()
    return agent


async def get_agent_by_id(session: AsyncSession, agent_id: uuid.UUID) -> Optional[Agent]:
    """Retrieves an Agent by primary key."""
    result = await session.execute(select(Agent).where(Agent.id == agent_id))
    return result.scalar_one_or_none()


async def list_agents(
    session: AsyncSession,
    environment: Optional[str] = None,
    status: Optional[str] = None,
    skip: int = 0,
    limit: int = 50,
) -> list[Agent]:
    """Lists registered agents with optional filters."""
    query = select(Agent)
    if environment:
        query = query.where(Agent.environment == environment)
    if status:
        query = query.where(Agent.status == status)
    query = query.order_by(Agent.created_at.desc()).offset(skip).limit(limit)
    result = await session.execute(query)
    return list(result.scalars().all())

