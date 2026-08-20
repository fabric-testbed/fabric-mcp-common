"""
The ``mcp_*`` Prometheus metric contract.

These names and label sets are a **contract**: the shipped Grafana dashboard
queries them, so every server that adopts this package gets a working dashboard
with no per-server editing.  Renaming a metric or changing a label set is a
breaking change for that dashboard.

Requires the ``metrics`` extra (``pip install fabric-mcp-common[metrics]``).

Cardinality
-----------
Prometheus keeps one time series per distinct label combination, for the life of
the process.  Two labels here are dangerous on a public endpoint:

* ``client_ip`` — one series per source address.  A scanner sweeping the server
  mints a series per address and never releases them.  **Off by default**; see
  :func:`configure`.
* ``path`` — safe only while routes are static.  A route carrying an id
  (``/slices/<uuid>``) makes it unbounded, so paths are normalised through
  :func:`normalize_path`.

``user_uuid`` / ``user_email`` are bounded by your user base, which is a real but
manageable cost — one series per active user per metric.
"""
from __future__ import annotations

import re
from typing import Iterable, Optional

try:
    from prometheus_client import Counter, Gauge, Histogram
    from prometheus_client import REGISTRY as DEFAULT_REGISTRY
except ImportError as e:  # pragma: no cover - depends on install extras
    raise ImportError(
        "fabric_mcp_common.metrics requires prometheus-client: "
        "pip install fabric-mcp-common[metrics]"
    ) from e

#: Latency histogram buckets, in seconds.
BUCKETS = (0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30)

#: Placeholder substituted for high-cardinality path segments.
PATH_PLACEHOLDER = "{id}"

#: Label value used when client-IP labelling is disabled.
IP_DISABLED = "disabled"

_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_LONG_HEX_RE = re.compile(r"\b[0-9a-fA-F]{16,}\b")
_DIGITS_RE = re.compile(r"\b\d+\b")

# ---------------------------------------------------------------------------
# Runtime configuration
# ---------------------------------------------------------------------------

_client_ip_enabled = False


def configure(*, client_ip_labels: bool = False) -> None:
    """Set cardinality policy for this process.

    Call once at startup, before serving traffic.

    Args:
        client_ip_labels: Record real client IPs in ``client_ip`` labels.  Leave
            false unless the endpoint is not publicly reachable or you have a
            series budget for it; when false the label is still present (so the
            dashboard's queries keep working) with the constant value
            :data:`IP_DISABLED`.
    """
    global _client_ip_enabled
    _client_ip_enabled = bool(client_ip_labels)


def client_ip_labels_enabled() -> bool:
    """Whether real client IPs are being recorded."""
    return _client_ip_enabled


def ip_label(client_ip: Optional[str]) -> str:
    """Render *client_ip* for use as a label value, honouring :func:`configure`."""
    if not _client_ip_enabled:
        return IP_DISABLED
    return client_ip or "unknown"


def normalize_path(path: str, *, max_segments: int = 12) -> str:
    """Collapse high-cardinality segments of a URL path.

    Replaces UUIDs, long hex strings and bare integers with
    :data:`PATH_PLACEHOLDER`, and truncates pathologically deep paths, so that
    ``/slices/2f1c.../nodes/7`` becomes ``/slices/{id}/nodes/{id}``.
    """
    if not path:
        return "/"
    out = _UUID_RE.sub(PATH_PLACEHOLDER, path)
    out = _LONG_HEX_RE.sub(PATH_PLACEHOLDER, out)
    out = _DIGITS_RE.sub(PATH_PLACEHOLDER, out)
    parts = out.split("/")
    if len(parts) > max_segments:
        out = "/".join(parts[:max_segments] + ["..."])
    return out


# ---------------------------------------------------------------------------
# HTTP metrics
# ---------------------------------------------------------------------------

mcp_http_requests_total = Counter(
    "mcp_http_requests_total",
    "Total HTTP requests",
    ["method", "path", "status"],
)

mcp_http_request_duration_seconds = Histogram(
    "mcp_http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["method", "path"],
    buckets=BUCKETS,
)

mcp_http_requests_in_progress = Gauge(
    "mcp_http_requests_in_progress",
    "Currently active HTTP requests",
    ["method"],
)

# ---------------------------------------------------------------------------
# Tool call metrics
# ---------------------------------------------------------------------------

mcp_tool_calls_total = Counter(
    "mcp_tool_calls_total",
    "Total tool calls",
    ["tool", "user_uuid", "user_email", "project_name", "status"],
)

mcp_tool_call_duration_seconds = Histogram(
    "mcp_tool_call_duration_seconds",
    "Tool execution latency in seconds",
    ["tool"],
    buckets=BUCKETS,
)

# ---------------------------------------------------------------------------
# Rate limit metrics
# ---------------------------------------------------------------------------

mcp_rate_limit_hits_total = Counter(
    "mcp_rate_limit_hits_total",
    "Total rate limit 429 responses",
    ["key_type"],
)

# ---------------------------------------------------------------------------
# Security metrics
# ---------------------------------------------------------------------------

mcp_auth_failures_total = Counter(
    "mcp_auth_failures_total",
    "Authentication failures",
    ["reason", "client_ip"],
)

mcp_requests_by_ip_total = Counter(
    "mcp_requests_by_ip_total",
    "Requests by client IP (for geo/anomaly detection)",
    ["client_ip"],
)

mcp_auth_success_total = Counter(
    "mcp_auth_success_total",
    "Successful authentications by user and IP",
    ["user_uuid", "user_email", "client_ip"],
)

# ---------------------------------------------------------------------------
# Per-user metrics
# ---------------------------------------------------------------------------

mcp_requests_by_user_total = Counter(
    "mcp_requests_by_user_total",
    "Per-user request count",
    ["user_uuid", "user_email"],
)

mcp_requests_by_user_path_total = Counter(
    "mcp_requests_by_user_path_total",
    "Per-user per-path request count",
    ["user_uuid", "user_email", "method", "path"],
)


#: Every metric object in the contract, for introspection and tests.
ALL_METRICS = (
    mcp_http_requests_total,
    mcp_http_request_duration_seconds,
    mcp_http_requests_in_progress,
    mcp_tool_calls_total,
    mcp_tool_call_duration_seconds,
    mcp_rate_limit_hits_total,
    mcp_auth_failures_total,
    mcp_requests_by_ip_total,
    mcp_auth_success_total,
    mcp_requests_by_user_total,
    mcp_requests_by_user_path_total,
)

#: The contract's metric names exactly as they appear on ``/metrics``, and
#: therefore exactly as the bundled dashboard queries them.  Declared explicitly
#: rather than derived: these strings *are* the contract, and deriving them from
#: prometheus_client internals silently drops the ``_total`` suffix counters get.
METRIC_NAMES = (
    "mcp_http_requests_total",
    "mcp_http_request_duration_seconds",
    "mcp_http_requests_in_progress",
    "mcp_tool_calls_total",
    "mcp_tool_call_duration_seconds",
    "mcp_rate_limit_hits_total",
    "mcp_auth_failures_total",
    "mcp_requests_by_ip_total",
    "mcp_auth_success_total",
    "mcp_requests_by_user_total",
    "mcp_requests_by_user_path_total",
)


def metric_names() -> Iterable[str]:
    """The contract's metric names, as exposed on ``/metrics``."""
    return METRIC_NAMES


__all__ = [
    "ALL_METRICS",
    "BUCKETS",
    "DEFAULT_REGISTRY",
    "IP_DISABLED",
    "METRIC_NAMES",
    "PATH_PLACEHOLDER",
    "client_ip_labels_enabled",
    "configure",
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
]
