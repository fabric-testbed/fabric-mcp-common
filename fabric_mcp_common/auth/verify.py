"""
Cryptographic token verification against FABRIC Credential Manager JWKS.

Optional: requires the ``verify`` extra (``pip install fabric-mcp-common[verify]``),
which pulls in ``fabric_fss_utils``.  Everything else in this library works
without it.

This wraps ``fss_utils.jwt_validate.JWTValidator`` — the same validator
``fabrictestbed.util.utils.Utils.decode_token`` uses — rather than reimplementing
JWKS handling, so key fetching, caching and algorithm selection stay consistent
with the rest of the FABRIC stack.  On top of it this adds thread safety, typed
errors, and :class:`~fabric_mcp_common.auth.claims.TokenClaims` output.

Reach for this only when your server *terminates* authentication.  When tokens
are forwarded to a FABRIC API that validates them itself (the usual MCP proxy
case), the unverified decode in :mod:`fabric_mcp_common.auth.claims` is sufficient and
avoids a dependency on CredMgr availability.
"""
from __future__ import annotations

import logging
import threading
from datetime import timedelta
from typing import Any, Optional

from fabric_mcp_common.auth.claims import TokenClaims
from fabric_mcp_common.auth.errors import (
    ExpiredTokenError,
    InvalidTokenError,
    VerificationUnavailableError,
)

log = logging.getLogger("fabric.common.auth")

#: Default FABRIC Credential Manager host.
DEFAULT_CREDMGR_HOST = "cm.fabric-testbed.net"

#: Path of the JWKS endpoint on a Credential Manager host.
CERTS_PATH = "/credmgr/certs"

#: Default JWKS cache lifetime.
DEFAULT_REFRESH_PERIOD = timedelta(minutes=10)

# ValidateCode names that indicate a problem with our side, not the token.
_INFRASTRUCTURE_CODES = frozenset(
    {"UNABLE_TO_FETCH_KEYS", "UNABLE_TO_DECODE_KEYS", "UNABLE_TO_LOAD_KEYS"}
)


def credmgr_jwks_url(credmgr_host: str = DEFAULT_CREDMGR_HOST) -> str:
    """Build the JWKS URL for a Credential Manager host.

    Accepts a bare host (``cm.fabric-testbed.net``) or a full base URL.
    """
    host = credmgr_host.strip().rstrip("/")
    if not host.startswith(("http://", "https://")):
        host = f"https://{host}"
    return f"{host}{CERTS_PATH}"


class CredMgrVerifier:
    """Verifies FABRIC identity tokens against CredMgr's published JWKS.

    Args:
        credmgr_host: Credential Manager host.  Ignored when *jwks_url* is set.
        jwks_url: Explicit JWKS endpoint, overriding *credmgr_host*.
        audience: Expected ``aud`` claim (a CILogon client id such as
            ``cilogon:/client_id/1234567890``).  Audience is not checked when
            omitted.
        refresh_period: How long fetched signing keys stay cached.
        verify_exp: Enforce the ``exp`` claim.  On by default — the opposite of
            the underlying ``fss_utils`` default, because a verifier that
            accepts expired tokens provides little protection.
    """

    def __init__(
        self,
        *,
        credmgr_host: str = DEFAULT_CREDMGR_HOST,
        jwks_url: Optional[str] = None,
        audience: Optional[str] = None,
        refresh_period: timedelta = DEFAULT_REFRESH_PERIOD,
        verify_exp: bool = True,
    ) -> None:
        self.jwks_url = jwks_url or credmgr_jwks_url(credmgr_host)
        self.audience = audience
        self.refresh_period = refresh_period
        self.verify_exp = verify_exp
        self._lock = threading.Lock()
        self._validator: Any = None

    # -- internals -------------------------------------------------------

    def _get_validator(self) -> Any:
        """Lazily build the underlying ``fss_utils`` validator."""
        if self._validator is None:
            try:
                from fss_utils.jwt_validate import JWTValidator
            except ImportError as e:  # pragma: no cover - depends on install extras
                raise VerificationUnavailableError(
                    "Token verification requires fabric_fss_utils: "
                    "pip install fabric-mcp-common[verify]"
                ) from e
            self._validator = JWTValidator(
                url=self.jwks_url,
                refresh_period=self.refresh_period,
                audience=self.audience,
            )
        return self._validator

    def refresh_keys(self) -> None:
        """Invalidate the cached JWKS so the next verify re-fetches keys."""
        with self._lock:
            if self._validator is not None:
                self._validator.keysFetched = None

    # -- public API ------------------------------------------------------

    def verify(self, token: str) -> TokenClaims:
        """Verify *token*'s signature and return its claims.

        Args:
            token: Compact JWS string.

        Returns:
            Verified :class:`~fabric_mcp_common.auth.claims.TokenClaims`
            (``claims.verified`` is true).

        Raises:
            ExpiredTokenError: The signature is valid but the token has expired.
            InvalidTokenError: The token is unparsable, unsigned by a known key,
                or fails signature/audience checks.
            VerificationUnavailableError: Signing keys could not be fetched or
                the ``verify`` extra is not installed — a server-side fault,
                not a bad credential.
        """
        if not token:
            raise InvalidTokenError("No token supplied for verification.")

        validator = self._get_validator()
        with self._lock:
            code, result = validator.validate_jwt(token=token, verify_exp=self.verify_exp)

        code_name = getattr(code, "name", str(code))
        if code_name == "VALID":
            return TokenClaims(result, verified=True)

        detail = _describe(code, result)

        if code_name in _INFRASTRUCTURE_CODES:
            log.error("Unable to verify token: %s", detail)
            raise VerificationUnavailableError(f"Unable to verify token: {detail}")

        if code_name == "INVALID" and _is_expiry_error(result):
            raise ExpiredTokenError(f"Authentication Required: Token has expired ({detail}).")

        raise InvalidTokenError(f"Authentication Required: {detail}")


def verify_token(
    token: str,
    *,
    credmgr_host: str = DEFAULT_CREDMGR_HOST,
    audience: Optional[str] = None,
    verify_exp: bool = True,
) -> TokenClaims:
    """One-shot token verification.

    Builds a throwaway :class:`CredMgrVerifier`, so it re-fetches JWKS on every
    call.  Keep a long-lived verifier instead for anything request-scoped.
    """
    return CredMgrVerifier(
        credmgr_host=credmgr_host, audience=audience, verify_exp=verify_exp
    ).verify(token)


def _describe(code: Any, result: Any) -> str:
    """Render a ``ValidateCode`` plus optional exception as one message."""
    interpret = getattr(code, "interpret", None)
    if callable(interpret):
        try:
            return str(interpret(exception=result))
        except Exception:  # pragma: no cover - defensive
            pass
    name = getattr(code, "name", str(code))
    return f"{name}: {result}" if result else str(name)


def _is_expiry_error(exc: Any) -> bool:
    """Whether a PyJWT exception object represents an expired signature."""
    if exc is None:
        return False
    try:
        from jwt import ExpiredSignatureError

        if isinstance(exc, ExpiredSignatureError):
            return True
    except ImportError:  # pragma: no cover - jwt ships with fss_utils
        pass
    return type(exc).__name__ == "ExpiredSignatureError"


__all__ = [
    "CERTS_PATH",
    "DEFAULT_CREDMGR_HOST",
    "DEFAULT_REFRESH_PERIOD",
    "CredMgrVerifier",
    "credmgr_jwks_url",
    "verify_token",
]
