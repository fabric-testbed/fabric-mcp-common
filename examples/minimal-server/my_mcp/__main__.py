"""
Entry point: wire the server and run it.

Ordering matters in one place — ``configure_logging()`` runs *before* the imports
that log, so their import-time output is formatted and levelled correctly.
"""
from __future__ import annotations

import logging

from my_mcp.observability import configure_logging

configure_logging()

from fastmcp import FastMCP  # noqa: E402

from my_mcp.config import config  # noqa: E402
from my_mcp.tools.example import TOOLS  # noqa: E402

log = logging.getLogger("my_mcp")

mcp = FastMCP(name="my-mcp", instructions="Example FABRIC MCP server.")

for tool_name, fn in TOOLS.items():
    mcp.tool(fn, name=tool_name)


def _http_middleware() -> list:
    """Starlette middleware for HTTP transport, in the order it should run."""
    from starlette.middleware import Middleware

    from fabric_mcp_common.metrics import MetricsMiddleware, SecurityMetricsMiddleware
    from fabric_mcp_common.metrics import configure as configure_metrics

    # client_ip labels are off by default in the library: one Prometheus series
    # per source address is unbounded on a public endpoint. Opt in deliberately.
    configure_metrics(client_ip_labels=config.metrics_client_ip_labels)

    return [
        Middleware(MetricsMiddleware),
        Middleware(SecurityMetricsMiddleware),
    ]


def main() -> None:
    if config.transport == "stdio":
        # stdio reserves stdout for JSON-RPC. Never print to stdout here; the
        # library's logging handler writes to stderr for exactly this reason.
        log.info("Starting my-mcp in local/stdio mode")
        mcp.run(transport="stdio")
        return

    middleware = _http_middleware() if config.metrics_enabled else []

    if config.metrics_enabled:
        from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
        from starlette.responses import Response

        @mcp.custom_route("/metrics", methods=["GET"])
        async def metrics(_request):  # noqa: ANN001
            return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    # Rate limiting needs the FastAPI/Starlette app, which FastMCP builds inside
    # run(). If you need it, build the ASGI app explicitly instead:
    #
    #     app = mcp.http_app(middleware=middleware)
    #     register_rate_limiter(app)
    #     uvicorn.run(app, host=config.host, port=config.port)
    #
    # See rate_limit.py — and set RATE_LIMIT_TRUSTED_PROXIES to your proxy.
    log.info("Starting my-mcp on http://%s:%s", config.host, config.port)
    mcp.run(
        transport="http",
        host=config.host,
        port=config.port,
        middleware=middleware or None,
    )


if __name__ == "__main__":
    main()
