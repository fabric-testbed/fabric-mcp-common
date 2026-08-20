"""
FastMCP adapter.

Collapses the pattern repeated across FABRIC MCP tool modules —

.. code-block:: python

    headers = get_http_headers(include={"authorization"}) or {}
    id_token = extract_bearer_token(headers)
    if not id_token:
        raise ValueError("Authentication Required: ...")

— into a single :class:`~fabric_mcp_common.auth.resolver.TokenResolver` that also works
under stdio transport, where there is no HTTP request to read a header from.

Requires ``fastmcp`` only when an HTTP request context is actually consulted;
:func:`request_headers` degrades to ``{}`` if it is absent, so local-mode
servers need not install it.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, Iterable, Optional, Sequence, Union

from fabric_mcp_common.auth.bearer import (
    AUTHORIZATION_HEADER,
    BEARER_SCHEME,
    extract_bearer_token,
)
from fabric_mcp_common.auth.claims import TokenClaims
from fabric_mcp_common.net import DEFAULT_FORWARDED_HEADERS, client_ip_from_headers
from fabric_mcp_common.auth.providers import (
    TOKEN_ENV,
    TOKEN_LOCATION_ENV,
    BaseTokenProvider,
    ChainTokenProvider,
    EnvTokenProvider,
    FileTokenProvider,
    HeaderTokenProvider,
    TokenProvider,
)
from fabric_mcp_common.auth.resolver import AuthContext, TokenResolver, TokenVerifier

log = logging.getLogger("fabric.common.auth")


def fastmcp_available() -> bool:
    """Whether ``fastmcp``'s request-context helpers can be imported."""
    try:
        from fastmcp.server.dependencies import get_http_headers  # noqa: F401
    except Exception:
        return False
    return True


def request_headers(
    include: Optional[Iterable[str]] = (AUTHORIZATION_HEADER,),
) -> Dict[str, str]:
    """Headers of the in-flight FastMCP HTTP request.

    Args:
        include: Header names to request from FastMCP.  ``None`` asks for all.

    Returns:
        The headers, or ``{}`` when there is no HTTP request in scope — stdio
        transport, background tasks, or ``fastmcp`` not installed.  Returning an
        empty mapping rather than raising lets one code path serve both
        transports.
    """
    try:
        from fastmcp.server.dependencies import get_http_headers
    except Exception:
        log.debug("fastmcp request context unavailable", exc_info=True)
        return {}

    try:
        headers = get_http_headers(include=set(include)) if include else get_http_headers()
    except Exception:
        # Raised when called outside a request scope, which is normal in stdio mode.
        log.debug("No FastMCP HTTP request in scope", exc_info=True)
        return {}
    return dict(headers or {})


class RequestTokenProvider(BaseTokenProvider):
    """Reads the bearer token from the in-flight FastMCP HTTP request.

    Safe to construct once at import time and share: headers are looked up per
    call, from the ambient request context.
    """

    source = "bearer"

    def __init__(
        self,
        *,
        header_name: str = AUTHORIZATION_HEADER,
        scheme: str = BEARER_SCHEME,
    ) -> None:
        self._delegate = HeaderTokenProvider(
            lambda: request_headers((header_name,)),
            header_name=header_name,
            scheme=scheme,
        )

    def get_token(self) -> Optional[str]:
        return self._delegate.get_token()


def local_token_provider(
    token_location: Optional[Union[str, os.PathLike]] = None,
    *,
    env_var: str = TOKEN_LOCATION_ENV,
    token_env: str = TOKEN_ENV,
) -> ChainTokenProvider:
    """Token source for local/stdio mode: token file, then bare env var.

    Args:
        token_location: Explicit token file path.  Defaults to ``$FABRIC_TOKEN_LOCATION``.
        env_var: Environment variable naming the token file.
        token_env: Environment variable holding a bare token, tried as a fallback.
    """
    return ChainTokenProvider(
        FileTokenProvider(token_location, env_var=env_var, strict=False),
        EnvTokenProvider(token_env),
    )


def build_provider(
    *,
    local_mode: bool,
    token_location: Optional[Union[str, os.PathLike]] = None,
    header_name: str = AUTHORIZATION_HEADER,
    scheme: str = BEARER_SCHEME,
    allow_header_in_local_mode: bool = True,
) -> TokenProvider:
    """Build the token source appropriate to the server's mode.

    Args:
        local_mode: True for stdio/local deployments, false for HTTP server mode.
        token_location: Explicit token file path for local mode.
        header_name: Header carrying credentials in server mode.
        scheme: Authentication scheme in server mode.
        allow_header_in_local_mode: Also accept a bearer header in local mode,
            for local servers reached over HTTP.  Header wins when present.

    Returns:
        A provider; in server mode strictly the request header, so a local token
        file can never be used to serve someone else's request.
    """
    request_provider = RequestTokenProvider(header_name=header_name, scheme=scheme)
    if not local_mode:
        return request_provider

    local = local_token_provider(token_location)
    if allow_header_in_local_mode:
        return ChainTokenProvider(request_provider, local)
    return local


def build_resolver(
    *,
    local_mode: bool,
    token_location: Optional[Union[str, os.PathLike]] = None,
    verifier: Optional[TokenVerifier] = None,
    enforce_expiry: bool = False,
    leeway: float = 0.0,
    header_name: str = AUTHORIZATION_HEADER,
    scheme: str = BEARER_SCHEME,
    allow_header_in_local_mode: bool = True,
) -> TokenResolver:
    """Build the resolver a FABRIC MCP server should share across its tools.

    Example:
        .. code-block:: python

            RESOLVER = build_resolver(local_mode=config.local_mode)

            def my_tool(...):
                auth = RESOLVER.resolve()          # raises if unauthenticated
                fm = FabricManagerV2(id_token=auth.token, ...)
    """
    provider = build_provider(
        local_mode=local_mode,
        token_location=token_location,
        header_name=header_name,
        scheme=scheme,
        allow_header_in_local_mode=allow_header_in_local_mode,
    )
    return TokenResolver(
        provider,
        verifier=verifier,
        enforce_expiry=enforce_expiry,
        leeway=leeway,
    )


def current_token(
    *,
    header_name: str = AUTHORIZATION_HEADER,
    scheme: str = BEARER_SCHEME,
) -> Optional[str]:
    """The in-flight request's bearer token, or ``None``.

    A one-liner replacement for the ``get_http_headers`` + ``extract_bearer_token``
    pair.  Does not consider local-mode token files — use
    :func:`build_resolver` when both modes must work.
    """
    return RequestTokenProvider(header_name=header_name, scheme=scheme).get_token()


def current_claims(
    *,
    header_name: str = AUTHORIZATION_HEADER,
    scheme: str = BEARER_SCHEME,
) -> TokenClaims:
    """Unverified claims for the in-flight request; empty when unauthenticated."""
    return TokenClaims.from_token(current_token(header_name=header_name, scheme=scheme))


def require_current_token(
    *,
    header_name: str = AUTHORIZATION_HEADER,
    scheme: str = BEARER_SCHEME,
) -> str:
    """The in-flight request's bearer token.

    Raises:
        MissingTokenError: When the request carries no usable bearer token.
    """
    return RequestTokenProvider(header_name=header_name, scheme=scheme).require_token()


#: Headers a tool wrapper typically needs for tracing: credentials, request id,
#: and the proxy headers carrying the client IP.
TRACING_HEADERS = (
    AUTHORIZATION_HEADER,
    "x-request-id",
    *DEFAULT_FORWARDED_HEADERS,
)


def current_client_ip(
    headers: Optional[Dict[str, str]] = None,
    *,
    forwarded_headers: Sequence[str] = DEFAULT_FORWARDED_HEADERS,
    default: str = "",
) -> str:
    """Client IP of the in-flight request, from its proxy headers.

    FastMCP tools see headers rather than a request object, so there is no socket
    peer to fall back to — hence the ``""`` default rather than ``"unknown"``.

    Args:
        headers: Pre-fetched headers.  Fetched from the request context when omitted.
        forwarded_headers: Header names to consult, highest precedence first.
        default: Returned when no header identified an IP.
    """
    if headers is None:
        headers = request_headers(forwarded_headers)
    return client_ip_from_headers(headers, forwarded_headers=forwarded_headers) or default


def current_trace_context(headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Identity and tracing fields for the in-flight request.

    One header fetch and one JWT decode, yielding everything a tool-logging
    wrapper needs.  Never raises, and never includes the token.

    Args:
        headers: Pre-fetched headers.  Fetched from the request context when omitted.

    Returns:
        ``request_id`` (``None`` when the client sent none, so the caller can
        generate one), plus ``user_sub``, ``user_email``, ``user_uuid``,
        ``project_name``, ``project_uuid`` and ``client_ip`` — empty strings when
        unauthenticated.
    """
    if headers is None:
        headers = request_headers(TRACING_HEADERS)
    lowered = {k.lower(): v for k, v in headers.items()}
    claims = TokenClaims.from_token(
        extract_bearer_token(headers) if headers else None
    )
    return {
        "request_id": lowered.get("x-request-id") or None,
        "user_sub": claims.sub or "",
        "user_email": claims.email or "",
        "user_uuid": claims.uuid or "",
        "project_name": claims.project_name or "",
        "project_uuid": claims.project_uuid or "",
        "client_ip": current_client_ip(headers),
    }


__all__ = [
    "TRACING_HEADERS",
    "AuthContext",
    "RequestTokenProvider",
    "TokenResolver",
    "build_provider",
    "build_resolver",
    "current_claims",
    "current_client_ip",
    "current_token",
    "current_trace_context",
    "fastmcp_available",
    "local_token_provider",
    "request_headers",
    "require_current_token",
]
