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
    OVERWRITING_FORWARDED_HEADER,
    UNKNOWN_IP,
    client_ip_from_headers,
    peer_in_networks,
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


def peer_ip(request: Any, default: str = UNKNOWN_IP) -> str:
    """The socket peer's address — the one thing a remote caller cannot forge."""
    host = getattr(getattr(request, "client", None), "host", None)
    return host or default


def trusted_client_ip(
    request: Any,
    *,
    trusted_proxies: Sequence[str] = (),
    header: str = OVERWRITING_FORWARDED_HEADER,
    default: Optional[str] = None,
) -> str:
    """Client address usable for a *security* decision.

    Honours *header* only when the socket peer is one of *trusted_proxies*, and
    otherwise returns the peer.  That ordering is the point: the peer cannot be
    forged remotely, so it is what makes the header believable.

    Prefer this over :func:`client_ip` anywhere the result gates behaviour — a
    rate-limit bucket, an allowlist, a lockout counter.  :func:`client_ip` exists
    for logs and metric labels, where a spoofed value is misleading rather than a
    control bypass.

    Args:
        trusted_proxies: CIDRs or addresses permitted to assert the client
            address.  **Empty by default: trust nobody.**  List only the proxy
            itself — a whole private range covers every other container, VPN
            client and LAN host that can reach the port, any of which could then
            forge *header*.
        header: Header consulted, defaulting to
            :data:`~fabric_mcp_common.net.OVERWRITING_FORWARDED_HEADER`.  Do not
            pass ``x-forwarded-for``: proxies typically append to it, so its
            left-most entry stays caller-controlled even on a trusted hop.
        default: Returned when there is no peer at all.

    Note:
        With no *trusted_proxies* every caller behind a proxy collapses to the
        proxy's address — one shared bucket.  That is safe but can cap a whole
        service, so configure the proxy explicitly and say so at startup.
    """
    fallback = UNKNOWN_IP if default is None else default
    peer = getattr(getattr(request, "client", None), "host", None)
    if peer_in_networks(peer, trusted_proxies):
        # Case-insensitive, matching client_ip_from_headers: header names are
        # case-insensitive per RFC 9110, and not every request object lowercases.
        lowered = {
            k.lower(): v for k, v in _headers(request).items() if isinstance(k, str)
        }
        asserted = lowered.get(header.lower())
        if asserted:
            return str(asserted).strip()
    return peer or fallback


def rate_limit_key(
    request: Any,
    *,
    claim: str = "sub",
    require_verified: bool = True,
    trusted_proxies: Sequence[str] = (),
    header: str = OVERWRITING_FORWARDED_HEADER,
    default: Optional[str] = None,
) -> str:
    """Per-caller rate-limit key, derived only from unforgeable inputs.

    The key *is* the bucket, so anything a caller controls can be rotated for a
    fresh bucket per request — which bypasses the limit outright rather than
    merely skewing it.  Order:

    1. the token's *claim*, but only from signature-verified claims while
       *require_verified* is set;
    2. *header*, but only when the socket peer is one of *trusted_proxies*;
    3. the socket peer.

    Args:
        claim: Claim used as the key, ``sub`` by default.
        require_verified: Use *claim* only when the claims came from a
            signature-verified decode.  **On by default**, and leaving it on is
            strongly advised: :func:`request_claims` performs an *unverified*
            payload decode, and a JWT payload can be written by hand with no
            signing key, so an unverified claim is attacker-controlled.  Set it
            False only if something upstream has already authenticated the token
            and you accept per-caller keys a client can choose.
        trusted_proxies: Passed to :func:`trusted_client_ip`; empty means trust
            no forwarded header.
        header: Passed to :func:`trusted_client_ip`.
        default: Key used when nothing identifies the caller.  Pass the
            framework's own remote-address value — e.g. SlowAPI's
            ``get_remote_address(request)`` — to stay consistent with the rest of
            the limiter.

    .. versionchanged:: 0.3.0
        Previously used *claim* from an unverified decode and fell back to the
        left-most ``X-Forwarded-For`` entry, both of which a caller could set.
        Now verified-only and trusted-peer-gated by default.
    """
    claims = request_claims(request)
    if not require_verified or claims.verified:
        value = claims.get(claim)
        if value:
            return str(value)
    return trusted_client_ip(
        request,
        trusted_proxies=trusted_proxies,
        header=header,
        default=default,
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
    "OVERWRITING_FORWARDED_HEADER",
    "REASON_EXPIRED_TOKEN",
    "REASON_INVALID_JWT",
    "REASON_MALFORMED_HEADER",
    "REASON_MISSING_TOKEN",
    "UNKNOWN_IP",
    "auth_failure_reason",
    "client_ip",
    "identity",
    "identity_fields",
    "peer_ip",
    "rate_limit_key",
    "request_claims",
    "request_token",
    "trusted_client_ip",
]
