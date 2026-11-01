"""AegisMesh Model Context Protocol (MCP) Server Module.

Provides process-isolated, authenticated, policy-governed, and tamper-evident audited
MCP tool infrastructure over Streamable HTTP transport.
"""

from app.mcp.registry import ToolMetadata, ToolRegistry, registry
from app.mcp.server import app, create_mcp_server, get_mcp_asgi_app, mcp_server, run_mcp_server

__all__ = [
    "ToolMetadata",
    "ToolRegistry",
    "app",
    "create_mcp_server",
    "get_mcp_asgi_app",
    "mcp_server",
    "registry",
    "run_mcp_server",
]

