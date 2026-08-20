"""
Logging setup for MCP servers.

:func:`configure_logging` applies the arrangement these servers want: a single
stderr handler, application loggers at the operator's chosen level, third-party
libraries pinned to WARNING, and the root logger held at WARNING so an
unconfigured dependency cannot flood the log.

It takes the level and format as arguments rather than reading a config module,
so it stays usable by any server.
"""
from __future__ import annotations

import logging
import sys
from typing import Iterable, Sequence

from fabric_mcp_common import LOGGER_NAMESPACE
from fabric_mcp_common.logging.formatters import JsonFormatter

#: Human-readable log line format.
TEXT_FORMAT = "%(asctime)s %(levelname)s [%(name)s] %(message)s"

#: Timestamp format for :data:`TEXT_FORMAT`.
TEXT_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

#: Loggers pinned to at least WARNING — noisy libraries that would otherwise
#: flood output when the application level is DEBUG.
NOISY_LOGGERS: Sequence[str] = (
    # HTTP clients
    "httpx", "httpcore", "urllib3", "requests", "aiohttp",
    # Containers
    "docker", "dockerpty", "container",
    # Caches
    "redis", "aioredis", "hiredis",
    # Databases
    "sqlalchemy", "alembic", "asyncpg", "psycopg2",
    # Async internals
    "asyncio", "concurrent", "anyio",
    # Crypto / auth libraries
    "paramiko", "cryptography", "jwt", "oauthlib",
    # Clouds and SDKs
    "botocore", "boto3", "s3transfer", "kubernetes", "google", "azure",
    # Misc
    "watchfiles", "watchdog", "filelock", "charset_normalizer", "multipart",
    "starlette",
)

#: Web-framework loggers, held at INFO or the application level, whichever is higher.
FRAMEWORK_LOGGERS: Sequence[str] = (
    "uvicorn", "uvicorn.error", "uvicorn.access", "fastapi", "fastmcp",
)


def configure_logging(
    *,
    level: str = "INFO",
    fmt: str = "text",
    app_loggers: Iterable[str] = (),
    stream=None,
    noisy_loggers: Sequence[str] = NOISY_LOGGERS,
    framework_loggers: Sequence[str] = FRAMEWORK_LOGGERS,
) -> logging.Handler:
    """Configure process-wide logging.

    Args:
        level: Application log level name, e.g. ``"DEBUG"``.  Unrecognised names
            fall back to INFO.
        fmt: ``"text"`` or ``"json"``.
        app_loggers: Your own logger names to set to *level*.  This package's
            namespace (:data:`fabric_mcp_common.LOGGER_NAMESPACE`) is always
            included, so library diagnostics honour *level* rather than being
            silently clamped by the root logger.
        stream: Handler stream.  Defaults to ``sys.stderr`` — important for stdio
            transports, which reserve stdout for protocol messages.
        noisy_loggers: Loggers to pin to at least WARNING.
        framework_loggers: Loggers to pin to at least INFO.

    Returns:
        The installed handler, for callers that want to add another.
    """
    user_level = getattr(logging, str(level).upper(), logging.INFO)
    if not isinstance(user_level, int):
        user_level = logging.INFO

    root = logging.getLogger()
    root.setLevel(max(user_level, logging.WARNING))

    # Replace handlers so repeated calls (reload, tests) do not duplicate output.
    for existing in list(root.handlers):
        root.removeHandler(existing)

    handler = logging.StreamHandler(sys.stderr if stream is None else stream)
    if str(fmt).lower() == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter(fmt=TEXT_FORMAT, datefmt=TEXT_DATE_FORMAT))
    root.addHandler(handler)

    # Application loggers, plus this package's namespace. Setting the single
    # parent "fabric.common" covers every subpackage, including ones added later.
    for name in (*app_loggers, LOGGER_NAMESPACE):
        logger = logging.getLogger(name)
        logger.setLevel(user_level)
        logger.propagate = True

    noise_level = max(user_level, logging.WARNING)
    for name in noisy_loggers:
        logging.getLogger(name).setLevel(noise_level)

    framework_level = max(user_level, logging.INFO)
    for name in framework_loggers:
        logger = logging.getLogger(name)
        logger.setLevel(framework_level)
        logger.propagate = True

    return handler


def describe_configuration(level: str = "INFO") -> str:
    """One-line summary of the levels :func:`configure_logging` would apply."""
    user_level = getattr(logging, str(level).upper(), logging.INFO)
    return (
        f"app_level={logging.getLevelName(user_level)}, "
        f"root_level={logging.getLevelName(max(user_level, logging.WARNING))}, "
        f"framework_level={logging.getLevelName(max(user_level, logging.INFO))}"
    )


__all__ = [
    "FRAMEWORK_LOGGERS",
    "NOISY_LOGGERS",
    "TEXT_DATE_FORMAT",
    "TEXT_FORMAT",
    "configure_logging",
    "describe_configuration",
]
