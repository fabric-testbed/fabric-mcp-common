"""
Rate limiting for server mode.

Read this section before changing it — the defaults here are the result of several
real bypasses, and each line is load-bearing.

**The key is the bucket.** Anything a caller can change is something a caller can
rotate to get a fresh bucket per request, which bypasses the limit *entirely*
rather than merely skewing it. So the key may only come from inputs a caller
cannot forge.

**But it must also distinguish callers.** Behind a reverse proxy the socket peer
is the proxy for every request, so keying on it alone puts everyone in one bucket
and turns ``RATE_LIMIT`` into a cap for the whole service — a self-inflicted
denial of service.

Ordering that satisfies both, which :func:`rate_limit_key` implements:

1. the JWT claim, **only from signature-verified claims**;
2. ``X-Real-IP``, **only when the socket peer is a configured proxy**;
3. the socket peer.

Two traps worth naming explicitly:

* ``X-Forwarded-For`` must not decide a key. nginx sets it from
  ``$proxy_add_x_forwarded_for``, which *appends* to whatever the client sent, so
  its left-most entry stays caller-controlled even on a trusted hop. ``X-Real-IP``
  comes from ``$remote_addr``, which overwrites. The library defaults to the
  latter.
* An **unverified** claim is attacker input, not identity. A JWT payload is
  base64 and can be written by hand with no signing key. ``require_verified``
  defaults to True; leave it there unless something upstream authenticates the
  token and you accept caller-chosen keys.
"""
from __future__ import annotations

import logging
from typing import Any

from fabric_mcp_common.integrations.starlette import rate_limit_key as _rate_limit_key
from fabric_mcp_common.integrations.starlette import request_claims
from fabric_mcp_common.net import invalid_networks
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address
from starlette.requests import Request
from starlette.responses import JSONResponse

from my_mcp.config import config

log = logging.getLogger("my_mcp")


def rate_limit_identity(request: Request) -> tuple[str, str]:
    """The key and what kind of thing it is (``user`` or ``ip``).

    Returned together so the ``key_type`` metric label cannot disagree with the
    key actually used. Deriving the label separately is a real bug: it let a
    forged token report ``user`` for a request that was bucketed by address, so
    the dashboard overstated what the limiter was doing.
    """
    claims = request_claims(request)
    kind = "user" if (claims.verified and claims.sub) else "ip"
    key = _rate_limit_key(
        request,
        trusted_proxies=config.rate_limit_trusted_proxies,
        default=get_remote_address(request),
    )
    return key, kind


def rate_limit_key(request: Request) -> str:
    """Key function for SlowAPI."""
    return rate_limit_identity(request)[0]


def _rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    key, key_type = rate_limit_identity(request)
    log.warning(
        "Rate limit exceeded: %s (key=%s, path=%s)", exc.detail, key, request.url.path
    )

    try:
        if config.metrics_enabled:
            from fabric_mcp_common.metrics import mcp_rate_limit_hits_total

            mcp_rate_limit_hits_total.labels(key_type=key_type).inc()
    except Exception:
        # A broken counter must not turn a 429 into a 500.
        pass

    return JSONResponse(
        status_code=429,
        content={"error": "limit_exceeded", "details": f"Rate limit exceeded: {exc.detail}"},
    )


def register_rate_limiter(app: Any) -> None:
    """Install the limiter, warning about the two silent misconfigurations.

    Args:
        app: A Starlette or FastAPI application. Typed loosely on purpose so this
            module needs no framework import of its own — it only uses
            ``app.state``, ``add_middleware`` and ``add_exception_handler``.
    """
    if not config.rate_limit_enabled:
        log.info("Rate limiting is disabled")
        return

    malformed = invalid_networks(config.rate_limit_trusted_proxies)
    if malformed:
        # Reported once, not per request. A typo silently narrows the trusted set,
        # which collapses callers into one bucket — a capacity bug that otherwise
        # looks like nothing at all.
        log.warning(
            "Ignoring malformed RATE_LIMIT_TRUSTED_PROXIES entries: %s",
            ", ".join(malformed),
        )

    if not config.rate_limit_trusted_proxies:
        # Correct when nothing fronts this server. Behind a proxy it means every
        # caller shares one bucket, so say it out loud rather than let a
        # service-wide cap be discovered in production.
        log.warning(
            "RATE_LIMIT_TRUSTED_PROXIES is empty: keying on the socket peer. "
            "Correct if this server is reached directly; if a reverse proxy "
            "fronts it, every caller shares one bucket and %s becomes a limit "
            "for the whole service. Set it to the proxy address.",
            config.rate_limit,
        )

    app.state.limiter = Limiter(key_func=rate_limit_key, default_limits=[config.rate_limit])
    app.add_middleware(SlowAPIMiddleware)
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    log.info("Rate limiting enabled: %s", config.rate_limit)
