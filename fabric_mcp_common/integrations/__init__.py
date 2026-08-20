"""
Framework adapters.

Each submodule is optional and imported on demand:

* :mod:`fabric_mcp_common.integrations.fastmcp` — resolve the calling request's
  token inside a FastMCP tool, in either stdio (local) or HTTP (server) mode.
* :mod:`fabric_mcp_common.integrations.starlette` — identity, client IP,
  rate-limit keys and auth-failure classification for ASGI middleware.

Neither is imported by :mod:`fabric_mcp_common.auth` itself, so the core package stays
dependency-free.
"""
from __future__ import annotations

__all__: list = []
