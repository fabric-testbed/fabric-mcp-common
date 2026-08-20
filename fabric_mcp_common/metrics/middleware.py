"""
ASGI middleware populating the ``mcp_*`` metric contract.

Both middlewares are ``BaseHTTPMiddleware`` subclasses and take their identity
labels from :mod:`fabric_mcp_common.integrations.starlette`, so a single JWT
decode is shared across the whole middleware stack.
"""
from __future__ import annotations

import time
from typing import Any, Sequence

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from fabric_mcp_common.integrations.starlette import (
    auth_failure_reason,
    client_ip,
    request_claims,
)
from fabric_mcp_common.metrics.definitions import (
    ip_label,
    mcp_auth_failures_total,
    mcp_auth_success_total,
    mcp_http_request_duration_seconds,
    mcp_http_requests_in_progress,
    mcp_http_requests_total,
    mcp_requests_by_ip_total,
    mcp_requests_by_user_path_total,
    mcp_requests_by_user_total,
    normalize_path,
)

#: Paths excluded from instrumentation by default — scraping ``/metrics`` must
#: not inflate the metrics it reports.
DEFAULT_SKIP_PATHS: Sequence[str] = ("/metrics",)

#: Path prefixes where a missing token counts as an auth failure.
DEFAULT_PROTECTED_PREFIXES: Sequence[str] = ("/mcp",)

#: Label value for users with no email claim.
UNKNOWN_EMAIL = "unknown"


class MetricsMiddleware(BaseHTTPMiddleware):
    """Records HTTP request counts, latency, in-flight gauge, and per-user counters.

    Args:
        app: The ASGI app.
        skip_paths: Paths to leave uninstrumented.
        normalize_paths: Collapse id-like path segments before using them as
            label values.  Leave on unless your routes are known-static.
    """

    def __init__(
        self,
        app: Any,
        *,
        skip_paths: Sequence[str] = DEFAULT_SKIP_PATHS,
        normalize_paths: bool = True,
    ) -> None:
        super().__init__(app)
        self.skip_paths = tuple(skip_paths)
        self.normalize_paths = normalize_paths

    async def dispatch(self, request: Request, call_next) -> Response:
        method = request.method
        raw_path = request.url.path

        if raw_path in self.skip_paths:
            return await call_next(request)

        path = normalize_path(raw_path) if self.normalize_paths else raw_path

        mcp_http_requests_in_progress.labels(method=method).inc()
        start = time.perf_counter()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            return response
        finally:
            duration = time.perf_counter() - start
            mcp_http_requests_in_progress.labels(method=method).dec()
            mcp_http_request_duration_seconds.labels(method=method, path=path).observe(duration)
            mcp_http_requests_total.labels(method=method, path=path, status=str(status)).inc()

            # Per-user counters from the JWT. Best-effort: instrumentation must
            # never turn a served request into a failed one.
            try:
                claims = request_claims(request)
                if claims:
                    user_uuid = claims.uuid or ""
                    user_email = claims.email or ""
                    if user_uuid or user_email:
                        mcp_requests_by_user_total.labels(
                            user_uuid=user_uuid, user_email=user_email,
                        ).inc()
                        mcp_requests_by_user_path_total.labels(
                            user_uuid=user_uuid, user_email=user_email,
                            method=method, path=path,
                        ).inc()
            except Exception:
                pass


class SecurityMetricsMiddleware(BaseHTTPMiddleware):
    """Records authentication outcomes and per-IP request counts.

    Classifies each request as ``malformed_header``, ``missing_token``,
    ``invalid_jwt``, ``expired_token`` or fine, from a single unverified decode.

    Args:
        app: The ASGI app.
        protected_prefixes: Paths where a missing token is a failure.  A request
            to an open path without credentials is not counted as one.
        skip_paths: Paths to leave uninstrumented.
        leeway: Clock-skew tolerance, in seconds, for the expiry check.
    """

    def __init__(
        self,
        app: Any,
        *,
        protected_prefixes: Sequence[str] = DEFAULT_PROTECTED_PREFIXES,
        skip_paths: Sequence[str] = DEFAULT_SKIP_PATHS,
        leeway: float = 0.0,
    ) -> None:
        super().__init__(app)
        self.protected_prefixes = tuple(protected_prefixes)
        self.skip_paths = tuple(skip_paths)
        self.leeway = leeway

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path in self.skip_paths:
            return await call_next(request)

        ip = ip_label(client_ip(request))

        mcp_requests_by_ip_total.labels(client_ip=ip).inc()

        reason = auth_failure_reason(
            request, protected_prefixes=self.protected_prefixes, leeway=self.leeway
        )
        if reason:
            mcp_auth_failures_total.labels(reason=reason, client_ip=ip).inc()

        # A decodable token counts as a successful authentication attempt even
        # when it has expired: the two signals answer different questions
        # ("who is calling" vs "is the credential still good").
        claims = request_claims(request)
        if claims:
            mcp_auth_success_total.labels(
                user_uuid=claims.uuid or "",
                user_email=claims.email or UNKNOWN_EMAIL,
                client_ip=ip,
            ).inc()

        return await call_next(request)


__all__ = [
    "DEFAULT_PROTECTED_PREFIXES",
    "DEFAULT_SKIP_PATHS",
    "UNKNOWN_EMAIL",
    "MetricsMiddleware",
    "SecurityMetricsMiddleware",
]
