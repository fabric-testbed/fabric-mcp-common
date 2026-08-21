"""
Logging and the tool decorator.

Two things are easy to get wrong here, so they are spelled out:

1. ``app_loggers`` must list *your* logger names. The library always registers
   its own ``fabric.common`` namespace, so library diagnostics honour LOG_LEVEL
   instead of being clamped by the root logger — you do not need to add it.
2. ``make_tool_logger`` is a factory. Bind the logger name and the metrics gate
   once here, then use the plain decorator at every tool. Passing a *callable*
   for ``metrics_enabled`` defers the check to call time, so flipping config at
   runtime works.
"""
from __future__ import annotations

import logging

from fabric_mcp_common.logging import configure_logging as _configure_logging
from fabric_mcp_common.logging import make_tool_logger

from my_mcp.config import config

#: Your own logger names, raised to LOG_LEVEL. Everything under these is covered,
#: so one entry per top-level namespace is enough.
APP_LOGGERS = ("my_mcp", "my_mcp.tools")


def configure_logging() -> None:
    """Set up logging. Call this before importing anything that logs at import."""
    _configure_logging(
        level=config.log_level,
        fmt=config.log_format,
        app_loggers=APP_LOGGERS,
    )
    logging.getLogger("my_mcp").debug("Logging configured")


#: Decorator for tools: ``@tool_logger("my_tool")``.
#:
#: Per call it logs sanitised parameters at DEBUG, start/finish with duration and
#: result size at INFO, and errors with a traceback — attaching caller identity as
#: structured fields — and records the tool metrics. Parameters whose names look
#: credential-bearing (``token``, ``password``, ``*_key``, ``secret``, …) are
#: replaced with ``***REDACTED***``.
#:
#: ``trace_context`` and ``record_metrics`` are left unset on purpose: the library
#: resolves them to ``current_trace_context`` and ``record_tool_call`` itself.
tool_logger = make_tool_logger(
    logger="my_mcp.tools",
    metrics_enabled=lambda: config.metrics_enabled,
)
