"""SQLAlchemy declarative base class for all database entities."""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base class for all models in AegisMesh."""
    pass

