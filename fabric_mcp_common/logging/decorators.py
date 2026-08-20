"""
Tool-call logging for MCP servers.

:func:`make_tool_logger` is a *factory*: it binds the server's logger name,
metrics policy and trace-context source once, and returns a decorator with the
plain ``@tool_logger("name")`` signature.  That keeps per-tool call sites free of
configuration — a server with dozens of registered tools does not want each
decorator repeating the same wiring.
"""
from __future__ import annotations

import logging
import time
import uuid
from functools import wraps
from typing import Any, Callable, Dict, FrozenSet, Optional, Union

#: Parameter names whose values are replaced with :data:`REDACTED_VALUE`.
#: Matched as substrings, case-insensitively, so ``id_token`` and
#: ``ssh_private_key`` are both caught.
REDACT_PARAMS: FrozenSet[str] = frozenset(
    {"token", "password", "secret", "key", "credential", "auth"}
)

#: Parameters omitted from logs entirely.
SKIP_PARAMS: FrozenSet[str] = frozenset({"ctx"})

#: Substituted for redacted parameter values.
REDACTED_VALUE = "***REDACTED***"

#: Strings longer than this are truncated in logged parameters.
MAX_PARAM_CHARS = 200

#: Default logger for tool call lines.
DEFAULT_LOGGER = "fabric.common.tools"


def sanitize_params(
    kwargs: Dict[str, Any],
    *,
    redact: FrozenSet[str] = REDACT_PARAMS,
    skip: FrozenSet[str] = SKIP_PARAMS,
    max_chars: int = MAX_PARAM_CHARS,
) -> Dict[str, Any]:
    """Make tool parameters safe and compact enough to log.

    Redacts anything whose name looks credential-bearing, drops framework noise,
    and truncates long strings.

    Args:
        kwargs: The tool's keyword arguments.
        redact: Substrings marking a parameter as sensitive.
        skip: Parameter names to omit.
        max_chars: Truncation threshold for string values.
    """
    sanitized: Dict[str, Any] = {}
    for key, value in kwargs.items():
        if key in skip:
            continue
        lowered = key.lower()
        if any(secret in lowered for secret in redact):
            sanitized[key] = REDACTED_VALUE
        elif isinstance(value, str) and len(value) > max_chars:
            sanitized[key] = f"{value[:max_chars]}... ({len(value)} chars)"
        else:
            sanitized[key] = value
    return sanitized


def _result_size(result: Any) -> Optional[int]:
    """Best-effort size of a tool result, for performance analysis."""
    if isinstance(result, list):
        return len(result)
    if isinstance(result, dict):
        return result.get("count") or len(result)
    return None


def make_tool_logger(
    *,
    logger: Union[str, logging.Logger] = DEFAULT_LOGGER,
    trace_context: Optional[Callable[[], Dict[str, Any]]] = None,
    record_metrics: Optional[Callable[..., None]] = None,
    metrics_enabled: Union[bool, Callable[[], bool]] = False,
) -> Callable[[str], Callable]:
    """Build a ``@tool_logger("name")`` decorator for async MCP tools.

    The returned decorator logs invocation parameters (DEBUG), start and
    completion with duration and result size (INFO), and errors with a traceback
    (ERROR) — attaching caller identity to every line as structured ``extra``
    fields.

    Args:
        logger: Logger, or its name, that tool lines are emitted on.  Pass your
            server's existing tool logger to keep log queries working.
        trace_context: Zero-argument callable returning identity/tracing fields
            (``request_id``, ``user_sub``, ``user_email``, ``user_uuid``,
            ``project_name``, ``client_ip``).  Defaults to
            :func:`fabric_mcp_common.integrations.fastmcp.current_trace_context`.
            Failures are swallowed — tracing must not break a tool call.
        record_metrics: Callable invoked as
            ``record_metrics(tool=..., duration_seconds=..., status=...,
            user_uuid=..., user_email=..., project_name=...)``.  Defaults to
            :func:`fabric_mcp_common.metrics.record_tool_call` when metrics are
            enabled.
        metrics_enabled: Whether to record metrics.  Pass a callable to defer the
            decision to call time, so a config flag read after import is still
            honoured.

    Returns:
        A decorator taking the tool name.
    """
    log = logging.getLogger(logger) if isinstance(logger, str) else logger

    def _enabled() -> bool:
        return metrics_enabled() if callable(metrics_enabled) else bool(metrics_enabled)

    def _trace() -> Dict[str, Any]:
        fn = trace_context
        if fn is None:
            try:
                from fabric_mcp_common.integrations.fastmcp import current_trace_context

                fn = current_trace_context
            except Exception:
                return {}
        try:
            return fn() or {}
        except Exception:
            log.debug("Failed to collect trace context", exc_info=True)
            return {}

    def _metrics(**kwargs: Any) -> None:
        if not _enabled():
            return
        sink = record_metrics
        if sink is None:
            try:
                from fabric_mcp_common.metrics import record_tool_call

                sink = record_tool_call
            except Exception:
                return
        try:
            sink(**kwargs)
        except Exception:
            pass

    def _wrap(tool_name: str) -> Callable:
        def _decorate(fn: Callable) -> Callable:
            @wraps(fn)  # preserves __name__, __doc__, annotations for FastMCP
            async def _async_wrapper(*args: Any, **kwargs: Any) -> Any:
                trace = _trace()
                rid = trace.get("request_id") or uuid.uuid4().hex[:12]
                user_sub = trace.get("user_sub", "") or ""
                user_email = trace.get("user_email", "") or ""
                user_uuid = trace.get("user_uuid", "") or ""
                project_name = trace.get("project_name", "") or ""
                client_ip = trace.get("client_ip", "") or ""

                extra_base = {
                    "tool": tool_name,
                    "request_id": rid,
                    "user_sub": user_sub,
                    "user_email": user_email,
                    "user_uuid": user_uuid,
                    "project_name": project_name,
                    "client_ip": client_ip,
                }
                user_display = user_email or user_sub or ""

                sanitized = sanitize_params(kwargs)
                log.debug(
                    "[%s] invoked with params: %s",
                    tool_name,
                    sanitized,
                    extra={**extra_base, "params": sanitized},
                )

                start = time.perf_counter()
                if user_display:
                    log.info(
                        "[%s] >>> START (rid=%s, user=%s, ip=%s)",
                        tool_name, rid, user_display, client_ip, extra=extra_base,
                    )
                else:
                    log.info("[%s] >>> START (rid=%s)", tool_name, rid, extra=extra_base)

                try:
                    result = await fn(*args, **kwargs)
                except Exception as e:
                    dur_ms = round((time.perf_counter() - start) * 1000, 2)
                    _metrics(
                        tool=tool_name, duration_seconds=dur_ms / 1000, status="error",
                        user_uuid=user_uuid, user_email=user_email,
                        project_name=project_name,
                    )
                    log.exception(
                        "[%s] !!! ERROR after %.2fms: %s (rid=%s)",
                        tool_name, dur_ms, str(e), rid,
                        extra={**extra_base, "duration_ms": dur_ms, "error": str(e)},
                    )
                    raise

                dur_ms = round((time.perf_counter() - start) * 1000, 2)
                _metrics(
                    tool=tool_name, duration_seconds=dur_ms / 1000, status="ok",
                    user_uuid=user_uuid, user_email=user_email, project_name=project_name,
                )
                size = _result_size(result)
                log.info(
                    "[%s] <<< DONE in %.2fms (result_size=%s, rid=%s)",
                    tool_name, dur_ms, size, rid,
                    extra={**extra_base, "duration_ms": dur_ms, "result_size": size},
                )
                return result

            return _async_wrapper

        return _decorate

    return _wrap


__all__ = [
    "DEFAULT_LOGGER",
    "MAX_PARAM_CHARS",
    "REDACTED_VALUE",
    "REDACT_PARAMS",
    "SKIP_PARAMS",
    "make_tool_logger",
    "sanitize_params",
]
