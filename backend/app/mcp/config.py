"""Configuration module for AegisMesh Model Context Protocol (MCP) server."""

from app.core.config import settings

MCP_SERVER_HOST = settings.MCP_SERVER_HOST
MCP_SERVER_PORT = settings.MCP_SERVER_PORT
MCP_SERVER_PATH = settings.MCP_SERVER_PATH
MCP_SERVER_NAME = settings.MCP_SERVER_NAME
MCP_SERVER_VERSION = settings.MCP_SERVER_VERSION

__all__ = [
    "MCP_SERVER_HOST",
    "MCP_SERVER_PORT",
    "MCP_SERVER_PATH",
    "MCP_SERVER_NAME",
    "MCP_SERVER_VERSION",
]

