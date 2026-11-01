"""Model Context Protocol (MCP) Streamable HTTP Server for AegisMesh 2.0.

Provides an isolated, authenticated, and audited MCP endpoint over Streamable HTTP transport.
"""

import logging
from typing import Optional

from mcp.server import MCPServer
from mcp.server.auth.middleware.auth_context import AuthContextMiddleware
from mcp.server.auth.middleware.bearer_auth import BearerAuthBackend
from starlette.applications import Starlette
from starlette.middleware.authentication import AuthenticationMiddleware
import uvicorn

from app.core.config import settings
from app.mcp.registry import registry
from app.mcp.security.authentication import AegisMeshBearerAuthBackend, AegisMeshTokenVerifier

logger = logging.getLogger("aegismesh.mcp.server")


def create_mcp_server() -> MCPServer:
    """Creates and configures the core MCPServer instance with registered tools."""
    server = MCPServer(
        name=settings.MCP_SERVER_NAME,
        version=settings.MCP_SERVER_VERSION,
    )
    registry.bind_to_server(server)
    logger.info(
        "Initialized MCPServer '%s' v%s with %d registered tools.",
        settings.MCP_SERVER_NAME,
        settings.MCP_SERVER_VERSION,
        len(registry.list_all()),
    )
    return server


def get_mcp_asgi_app(server: Optional[MCPServer] = None) -> Starlette:
    """Creates the Starlette ASGI application for Streamable HTTP transport with authentication middleware."""
    target_server = server or create_mcp_server()
    starlette_app = target_server.streamable_http_app(
        streamable_http_path=settings.MCP_SERVER_PATH,
        host=settings.MCP_SERVER_HOST,
    )

    # Attach official MCP authentication context & Bearer verification middlewares
    starlette_app.add_middleware(AuthContextMiddleware)
    starlette_app.add_middleware(
        AuthenticationMiddleware,
        backend=AegisMeshBearerAuthBackend(AegisMeshTokenVerifier()),
    )

    return starlette_app


# Module-level instances for ASGI entrypoints (e.g., uvicorn app.mcp.server:app)
mcp_server = create_mcp_server()
app = get_mcp_asgi_app(mcp_server)


def run_mcp_server() -> None:
    """Runs the MCP Streamable HTTP server via uvicorn on the configured host and port."""
    logger.info(
        "Starting AegisMesh MCP Server on http://%s:%d%s",
        settings.MCP_SERVER_HOST,
        settings.MCP_SERVER_PORT,
        settings.MCP_SERVER_PATH,
    )
    uvicorn.run(
        "app.mcp.server:app",
        host=settings.MCP_SERVER_HOST,
        port=settings.MCP_SERVER_PORT,
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    run_mcp_server()
