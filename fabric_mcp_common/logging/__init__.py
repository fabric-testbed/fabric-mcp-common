"""
Structured logging for MCP servers.

Standard library only.

    from fabric_mcp_common.logging import configure_logging, make_tool_logger

    configure_logging(level="INFO", fmt="json", app_loggers=("myserver",))

    tool_logger = make_tool_logger(logger="myserver.tools", metrics_enabled=True)

    @tool_logger("my_tool")
    async def my_tool(...): ...

Note:
    This subpackage shadows the standard library's ``logging`` name only for
    code that writes ``from fabric_mcp_common import logging``.  Inside the
    package, absolute imports mean ``import logging`` is always the stdlib.
"""
from __future__ import annotations

from fabric_mcp_common.logging.config import (
    FRAMEWORK_LOGGERS,
    NOISY_LOGGERS,
    TEXT_DATE_FORMAT,
    TEXT_FORMAT,
    configure_logging,
    describe_configuration,
)
from fabric_mcp_common.logging.decorators import (
    DEFAULT_LOGGER,
    MAX_PARAM_CHARS,
    REDACT_PARAMS,
    REDACTED_VALUE,
    SKIP_PARAMS,
    make_tool_logger,
    sanitize_params,
)
from fabric_mcp_common.logging.formatters import DEFAULT_EXTRA_FIELDS, JsonFormatter

__all__ = [
    "DEFAULT_EXTRA_FIELDS",
    "DEFAULT_LOGGER",
    "FRAMEWORK_LOGGERS",
    "MAX_PARAM_CHARS",
    "NOISY_LOGGERS",
    "REDACTED_VALUE",
    "REDACT_PARAMS",
    "SKIP_PARAMS",
    "TEXT_DATE_FORMAT",
    "TEXT_FORMAT",
    "JsonFormatter",
    "configure_logging",
    "describe_configuration",
    "make_tool_logger",
    "sanitize_params",
]
