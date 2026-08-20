"""
ASGI / Starlette adapter for middleware that needs caller identity.

Covers the three things FABRIC MCP middlewares each re-derived by hand: the
client IP behind a reverse proxy, the caller's identity for log fields and
metrics labels, and a rate-limit key that degrades from user to IP.

Nothing here imports Starlette.  The functions duck-type the request object
(``.headers``, ``.url.path``, ``.client``, ``.state``), so they work with
Starlette, FastAPI, and any compatible request without adding a dependency.
"""
from __future__ import annotations

from typing import Any, Dict, Optional, Sequence

from fabric_mcp_common.auth.bearer import (
    AUTHORIZATION_HEADER,
    BEARER_SCHEME,
    STATE_ABSENT,
    STATE_MALFORMED,
    describe_authorization,
    extract_bearer_token,
)
from fabric_mcp_common.auth.claims import ANONYMOUS, TokenClaims
from fabric_mcp_common.net import (
    DEFAULT_FORWARDED_HEADERS,
    UNKNOWN_IP,
    client_ip_from_headers,
)

#: ``request.state`` attribute used to memoize decoded claims per request.
CLAIMS_STATE_ATTR = "fabric_token_claims"

# Auth failure reasons, matching the labels FABRIC MCP security metrics use.
REASON_MALFORMED_HEADER = "malformed_header"
REASON_MISSING_TOKEN = "missing_token"
REASON_INVALID_JWT = "invalid_jwt"
REASON_EXPIRED_TOKEN = "expired_token"


def _headers(request: Any) -> Dict[str, str]:
    """Best-effort plain-dict view of a request's headers."""
    headers = getattr(request, "headers", None)
    if headers is None:
        return {}
    try:
        return dict(headers)
    except (TypeError, ValueError):
        return {}


def client_ip(
    request: Any,
    *,
    forwarded_headers: Sequence[str] = DEFAULT_FORWARDED_HEADERS,
    default: str = UNKNOWN_IP,
) -> str:
    """Resolve the client IP, honouring reverse-proxy headers.

    Checks each of *forwarded_headers* in order, taking the left-most entry of a
    comma-separated list, then falls back to the socket peer.

    Warning:
        These headers are client-supplied and trivially spoofed unless a trusted
        proxy overwrites them.  Only meaningful when the app sits behind one.
    """
    forwarded = client_ip_from_headers(
        _headers(request), forwarded_headers=forwarded_headers
    )
    if forwarded:
        return forwarded
    client = getattr(request, "client", None)
    host = getattr(client, "host", None)
    return host or default


def request_token(
    request: Any,
    *,
    header_name: str = AUTHORIZATION_HEADER,
    scheme: str = BEARER_SCHEME,
) -> Optional[str]:
    """The bearer token on *request*, or ``None``."""
    return extract_bearer_token(_headers(request), header_name=header_name, scheme=scheme)


def request_claims(
    request: Any,
    *,
    header_name: str = AUTHORIZATION_HEADER,
    scheme: str = BEARER_SCHEME,
    cache: bool = True,
) -> TokenClaims:
    """Unverified claims for *request*, empty when unauthenticated.

    Memoizes on ``request.state`` so several middlewares in one stack decode the
    JWT once instead of once each.  Never raises.
    """
    state = getattr(request, "state", None)
    if cache and state is not None:
        cached = getattr(state, CLAIMS_STATE_ATTR, None)
        if isinstance(cached, TokenClaims):
            return cached

    claims = TokenClaims.from_token(
        request_token(request, header_name=header_name, scheme=scheme)
    )

    if cache and state is not None:
        try:
            setattr(state, CLAIMS_STATE_ATTR, claims)
        except Exception:  # pragma: no cover - exotic request objects
            pass
    return claims


def identity(request: Any, default: str = ANONYMOUS) -> str:
    """Human-facing caller identity for log lines."""
    return request_claims(request).identity(default)


def identity_fields(request: Any) -> Dict[str, Any]:
    """Structured log fields describing the caller.

    Returns the keys FABRIC MCP access logs already emit — ``user_sub``,
    ``user_email``, ``user_uuid``, ``project_uuid``, ``client_ip`` — never the
    token itself.
    """
    claims = request_claims(request)
    return {
        "user_sub": claims.sub or "",
        "user_email": claims.email or "",
        "user_uuid": claims.uuid or "",
        "project_uuid": claims.project_uuid or "",
        "client_ip": client_ip(request),
    }


def rate_limit_key(
    request: Any,
    *,
    claim: str = "sub",
    forwarded_headers: Sequence[str] = DEFAULT_FORWARDED_HEADERS,
    default: Optional[str] = None,
) -> str:
    """Per-caller rate-limit key.

    Uses the token's *claim* for authenticated requests so a user is limited
    consistently across addresses, and falls back to the client IP otherwise.

    Args:
        claim: Claim used as the key, ``sub`` by default.
        forwarded_headers: Proxy headers consulted for the IP fallback.
        default: Key used when neither the claim nor any address identifies the
            caller.  Pass the framework's own remote-address value — e.g.
            SlowAPI's ``get_remote_address(request)`` — to keep behaviour
            consistent with the rest of the limiter.  Defaults to
            :data:`UNKNOWN_IP`.
    """
    value = request_claims(request).get(claim)
    if value:
        return str(value)
    return client_ip(
        request,
        forwarded_headers=forwarded_headers,
        default=UNKNOWN_IP if default is None else default,
    )


def auth_failure_reason(
    request: Any,
    *,
    protected_prefixes: Sequence[str] = ("/mcp",),
    leeway: float = 0.0,
    now: Optional[float] = None,
) -> Optional[str]:
    """Classify *request*'s authentication state for metrics.

    Replaces per-middleware branching plus a second hand-rolled JWT decode for
    the expiry check.

    Args:
        protected_prefixes: Paths where a missing token counts as a failure.
            An unauthenticated request to an open path is not a failure.
        leeway: Clock-skew tolerance for the expiry check, in seconds.
        now: Override the current POSIX time (for testing).

    Returns:
        One of :data:`REASON_MALFORMED_HEADER`, :data:`REASON_MISSING_TOKEN`,
        :data:`REASON_INVALID_JWT`, :data:`REASON_EXPIRED_TOKEN`, or ``None``
        when the request is fine.

    Note:
        Based on an unverified decode, so this detects malformed and expired
        tokens but not forged signatures.  Pair with
        :class:`fabric_mcp_common.auth.verify.CredMgrVerifier` if that matters.
    """
    headers = _headers(request)
    state = describe_authorization(headers)

    if state == STATE_MALFORMED:
        return REASON_MALFORMED_HEADER

    if state == STATE_ABSENT:
        path = str(getattr(getattr(request, "url", None), "path", "") or "")
        if any(path.startswith(prefix) for prefix in protected_prefixes):
            return REASON_MISSING_TOKEN
        return None

    claims = request_claims(request)
    if not claims:
        return REASON_INVALID_JWT
    if claims.is_expired(leeway=leeway, now=now):
        return REASON_EXPIRED_TOKEN
    return None


__all__ = [
    "CLAIMS_STATE_ATTR",
    "DEFAULT_FORWARDED_HEADERS",
    "REASON_EXPIRED_TOKEN",
    "REASON_INVALID_JWT",
    "REASON_MALFORMED_HEADER",
    "REASON_MISSING_TOKEN",
    "UNKNOWN_IP",
    "auth_failure_reason",
    "client_ip",
    "identity",
    "identity_fields",
    "rate_limit_key",
    "request_claims",
    "request_token",
]
