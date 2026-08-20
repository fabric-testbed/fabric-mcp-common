"""
FABRIC token authentication for MCP servers and API clients.

Bearer extraction, JWT claim decoding, token sources, and optional JWKS
verification.  Depends on nothing outside the standard library; signature
verification and the framework adapters are opt-in.

Quick start — one resolver shared by every tool, working in both local (stdio)
and server (HTTP) mode:

.. code-block:: python

    from fabric_mcp_common.integrations.fastmcp import build_resolver

    RESOLVER = build_resolver(local_mode=False)

    def my_tool(...):
        auth = RESOLVER.resolve()      # MissingTokenError if unauthenticated
        log.info("call by %s", auth.identity)
        return upstream_call(id_token=auth.token)

Identity for logging or metrics, without any failure path:

.. code-block:: python

    from fabric_mcp_common.auth import TokenClaims

    claims = TokenClaims.from_token(token)
    log.info("user=%s project=%s", claims.identity(), claims.project_name)

Signature verification (:mod:`fabric_mcp_common.auth.verify`) needs the
``verify`` extra; the framework adapters under
:mod:`fabric_mcp_common.integrations` are imported on demand.
"""
from __future__ import annotations

from fabric_mcp_common.auth.bearer import (
    AUTHORIZATION_HEADER,
    BEARER_SCHEME,
    authorization_header,
    describe_authorization,
    extract_bearer_token,
    parse_authorization,
    redact_token,
)
from fabric_mcp_common.auth.claims import (
    ANONYMOUS,
    TokenClaims,
    decode_payload,
    decode_token_claims,
)
from fabric_mcp_common.auth.errors import (
    AuthError,
    ExpiredTokenError,
    InvalidTokenError,
    MissingTokenError,
    TokenSourceError,
    VerificationUnavailableError,
)
from fabric_mcp_common.auth.providers import (
    TOKEN_ENV,
    TOKEN_LOCATION_ENV,
    CallableTokenProvider,
    ChainTokenProvider,
    EnvTokenProvider,
    FileTokenProvider,
    HeaderTokenProvider,
    StaticTokenProvider,
    TokenProvider,
    read_token_from_file,
)
from fabric_mcp_common.auth.resolver import AuthContext, TokenResolver, TokenVerifier

__all__ = [
    # bearer
    "AUTHORIZATION_HEADER",
    "BEARER_SCHEME",
    "authorization_header",
    "describe_authorization",
    "extract_bearer_token",
    "parse_authorization",
    "redact_token",
    # claims
    "ANONYMOUS",
    "TokenClaims",
    "decode_payload",
    "decode_token_claims",
    # errors
    "AuthError",
    "ExpiredTokenError",
    "InvalidTokenError",
    "MissingTokenError",
    "TokenSourceError",
    "VerificationUnavailableError",
    # providers
    "TOKEN_ENV",
    "TOKEN_LOCATION_ENV",
    "CallableTokenProvider",
    "ChainTokenProvider",
    "EnvTokenProvider",
    "FileTokenProvider",
    "HeaderTokenProvider",
    "StaticTokenProvider",
    "TokenProvider",
    "read_token_from_file",
    # resolver
    "AuthContext",
    "TokenResolver",
    "TokenVerifier",
]


def __getattr__(name: str):
    """Lazily expose the optional verification API at package level."""
    if name in ("CredMgrVerifier", "verify_token", "credmgr_jwks_url"):
        from fabric_mcp_common.auth import verify

        return getattr(verify, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
