"""
fabric-mcp-common — shared plumbing for FABRIC MCP servers.

Extracted from the FABRIC API MCP server so that new MCP implementations get
authentication, instrumentation and logging for free instead of reimplementing
them — and so that every server reports the *same* metric names and log fields,
which is what makes a shared Grafana dashboard possible.

Subpackages, each importable on its own:

* :mod:`fabric_mcp_common.auth` — bearer extraction, JWT claims, token sources,
  optional JWKS verification.  Standard library only.
* :mod:`fabric_mcp_common.metrics` — the ``mcp_*`` Prometheus metric contract,
  ASGI middleware, and a tool-call recorder.  Needs the ``metrics`` extra.
* :mod:`fabric_mcp_common.logging` — structured JSON logging, level wiring, and
  a tool-logging decorator factory.  Standard library only.
* :mod:`fabric_mcp_common.integrations` — FastMCP and Starlette/ASGI adapters.

The shipped dashboard matching the metric contract lives at
``fabric_mcp_common/dashboards/mcp-server.json``; see
:func:`fabric_mcp_common.metrics.dashboard_path`.

Logging namespace: every module logs under ``fabric.common.*``.  Configuring
the single parent logger ``fabric.common`` captures all of it, including
subpackages added later::

    logging.getLogger("fabric.common").setLevel(logging.DEBUG)

or call :func:`fabric_mcp_common.logging.configure_logging`, which does it.
"""
from __future__ import annotations

__version__ = "0.2.0"

#: Parent logger for everything in this package.  Configure this one name to
#: capture all current and future subpackages.
LOGGER_NAMESPACE = "fabric.common"

__all__ = ["LOGGER_NAMESPACE", "__version__"]
