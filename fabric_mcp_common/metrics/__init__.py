"""
Prometheus instrumentation for MCP servers.

Importing this subpackage requires the ``metrics`` extra
(``pip install fabric-mcp-common[metrics]``); the rest of
:mod:`fabric_mcp_common` does not.

The metric names and label sets defined here are a contract shared with the
bundled Grafana dashboard, so adopting this package means the dashboard works
against your server unedited::

    from fabric_mcp_common.metrics import (
        MetricsMiddleware, SecurityMetricsMiddleware, configure, dashboard_path,
    )

    configure(client_ip_labels=False)     # see the cardinality note below
    app.add_middleware(MetricsMiddleware)
    app.add_middleware(SecurityMetricsMiddleware)
    print(dashboard_path())               # import this into Grafana

Cardinality: ``client_ip`` labelling is **off by default** because one series
per source address is unbounded on a public endpoint.  Existing deployments that
already depend on those labels should call ``configure(client_ip_labels=True)``
explicitly.
"""
from __future__ import annotations

import pathlib

from fabric_mcp_common.metrics.definitions import (
    ALL_METRICS,
    DEFAULT_REGISTRY,
    BUCKETS,
    IP_DISABLED,
    METRIC_NAMES,
    PATH_PLACEHOLDER,
    client_ip_labels_enabled,
    configure,
    ip_label,
    mcp_auth_failures_total,
    mcp_auth_success_total,
    mcp_http_request_duration_seconds,
    mcp_http_requests_in_progress,
    mcp_http_requests_total,
    mcp_rate_limit_hits_total,
    mcp_requests_by_ip_total,
    mcp_requests_by_user_path_total,
    mcp_requests_by_user_total,
    mcp_tool_call_duration_seconds,
    mcp_tool_calls_total,
    metric_names,
    normalize_path,
)
from fabric_mcp_common.metrics.middleware import (
    DEFAULT_PROTECTED_PREFIXES,
    DEFAULT_SKIP_PATHS,
    MetricsMiddleware,
    SecurityMetricsMiddleware,
)

#: Filename of the bundled dashboard, inside ``fabric_mcp_common/dashboards/``.
DASHBOARD_FILENAME = "mcp-server.json"


def dashboard_path() -> pathlib.Path:
    """Filesystem path to the bundled Grafana dashboard JSON.

    Ships as package data, so it is available from an installed wheel — point
    Grafana's dashboard provisioning at it, or copy it into your deployment.
    """
    return pathlib.Path(__file__).resolve().parent.parent / "dashboards" / DASHBOARD_FILENAME


def record_tool_call(
    *,
    tool: str,
    duration_seconds: float,
    status: str = "ok",
    user_uuid: str = "",
    user_email: str = "",
    project_name: str = "",
) -> None:
    """Record one tool invocation against the contract.

    Best-effort: never raises, so instrumentation cannot fail a served call.

    Args:
        tool: Registered tool name.
        duration_seconds: Wall-clock execution time.
        status: ``"ok"`` or ``"error"``.
        user_uuid: Caller's FABRIC user UUID, if known.
        user_email: Caller's email, if known.
        project_name: Caller's project name, if known.
    """
    try:
        mcp_tool_calls_total.labels(
            tool=tool,
            user_uuid=user_uuid,
            user_email=user_email,
            project_name=project_name,
            status=status,
        ).inc()
        mcp_tool_call_duration_seconds.labels(tool=tool).observe(duration_seconds)
    except Exception:
        pass


__all__ = [
    "ALL_METRICS",
    "BUCKETS",
    "DASHBOARD_FILENAME",
    "DEFAULT_REGISTRY",
    "DEFAULT_PROTECTED_PREFIXES",
    "DEFAULT_SKIP_PATHS",
    "IP_DISABLED",
    "METRIC_NAMES",
    "PATH_PLACEHOLDER",
    "MetricsMiddleware",
    "SecurityMetricsMiddleware",
    "client_ip_labels_enabled",
    "configure",
    "dashboard_path",
    "ip_label",
    "mcp_auth_failures_total",
    "mcp_auth_success_total",
    "mcp_http_request_duration_seconds",
    "mcp_http_requests_in_progress",
    "mcp_http_requests_total",
    "mcp_rate_limit_hits_total",
    "mcp_requests_by_ip_total",
    "mcp_requests_by_user_path_total",
    "mcp_requests_by_user_total",
    "mcp_tool_call_duration_seconds",
    "mcp_tool_calls_total",
    "metric_names",
    "normalize_path",
    "record_tool_call",
]
