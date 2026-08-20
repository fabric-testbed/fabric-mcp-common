"""
Token resolution: source → token → claims → :class:`AuthContext`.

:class:`TokenResolver` is the seam every tool implementation should depend on.
It composes a :class:`~fabric_mcp_common.auth.providers.TokenProvider` with optional
signature verification and expiry enforcement, and hands back a single object
carrying both the credential to forward upstream and the identity to log.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

try:  # pragma: no cover - typing_extensions fallback for older interpreters
    from typing import Protocol, runtime_checkable
except ImportError:  # pragma: no cover
    from typing_extensions import Protocol, runtime_checkable  # type: ignore

from fabric_mcp_common.auth.bearer import authorization_header, redact_token
from fabric_mcp_common.auth.claims import TokenClaims
from fabric_mcp_common.auth.errors import ExpiredTokenError, MissingTokenError
from fabric_mcp_common.auth.providers import TokenProvider

log = logging.getLogger("fabric.common.auth")


@runtime_checkable
class TokenVerifier(Protocol):
    """Validates a token cryptographically and returns its claims."""

    def verify(self, token: str) -> TokenClaims:
        """Verify *token*, raising an
        :class:`~fabric_mcp_common.auth.errors.AuthError` subclass on failure."""
        ...


class AuthContext:
    """An authenticated caller: the token, its claims, and where it came from.

    Attributes:
        token: The raw credential, to forward to upstream FABRIC services.
        claims: Decoded (and possibly verified) token claims.
        source: Label of the provider that supplied the token, e.g. ``"bearer"``
            or ``"file"``.
    """

    __slots__ = ("token", "claims", "source")

    def __init__(self, token: str, claims: TokenClaims, source: str = "unknown") -> None:
        self.token = token
        self.claims = claims
        self.source = source

    # -- identity shortcuts ----------------------------------------------

    @property
    def identity(self) -> str:
        """Best human-facing identifier — email, else name, sub, or uuid."""
        return self.claims.identity()

    @property
    def user_id(self) -> Optional[str]:
        """The OIDC ``sub`` claim."""
        return self.claims.sub

    @property
    def user_uuid(self) -> Optional[str]:
        """The FABRIC user UUID."""
        return self.claims.uuid

    @property
    def email(self) -> Optional[str]:
        """The user's email address."""
        return self.claims.email

    @property
    def project_uuid(self) -> Optional[str]:
        """UUID of the token's first project."""
        return self.claims.project_uuid

    @property
    def project_name(self) -> Optional[str]:
        """Name of the token's first project."""
        return self.claims.project_name

    @property
    def verified(self) -> bool:
        """Whether the token's signature was cryptographically verified."""
        return self.claims.verified

    # -- helpers ---------------------------------------------------------

    def authorization_header(self) -> Dict[str, str]:
        """An ``Authorization: Bearer <token>`` header for outbound calls."""
        return authorization_header(self.token)

    def log_fields(self) -> Dict[str, Any]:
        """Structured log fields for this caller — never includes the token."""
        return {
            "user_sub": self.claims.sub or "",
            "user_uuid": self.claims.uuid or "",
            "user_email": self.claims.email or "",
            "project_uuid": self.claims.project_uuid or "",
            "auth_source": self.source,
        }

    def __repr__(self) -> str:
        return (
            f"AuthContext(identity={self.identity!r}, source={self.source!r}, "
            f"token={redact_token(self.token)}, verified={self.verified})"
        )


class TokenResolver:
    """Resolves the caller's token and claims from a configured source.

    Args:
        provider: Where tokens come from.
        verifier: Optional signature verifier, e.g.
            :class:`fabric_mcp_common.auth.verify.CredMgrVerifier`.  When supplied,
            :meth:`resolve` returns verified claims.
        verify: Force verification on or off.  Defaults to true whenever a
            *verifier* is supplied.
        enforce_expiry: Reject tokens whose unverified ``exp`` claim has
            passed.  Off by default, matching the FABRIC convention that
            upstream services are the authority on token validity; turn it on
            to fail fast at the edge.
        leeway: Clock-skew tolerance in seconds for expiry checks.
    """

    def __init__(
        self,
        provider: TokenProvider,
        *,
        verifier: Optional[TokenVerifier] = None,
        verify: Optional[bool] = None,
        enforce_expiry: bool = False,
        leeway: float = 0.0,
    ) -> None:
        self.provider = provider
        self.verifier = verifier
        self.verify = (verifier is not None) if verify is None else bool(verify)
        if self.verify and verifier is None:
            raise ValueError("verify=True requires a verifier")
        self.enforce_expiry = enforce_expiry
        self.leeway = leeway

    # -- token access ----------------------------------------------------

    def token(self) -> Optional[str]:
        """The caller's raw token, or ``None`` when unauthenticated."""
        return self.provider.get_token()

    def require_token(self) -> str:
        """The caller's raw token.

        Logs at debug only: the missing token is already signalled by the
        exception, and it is the application — which owns its logger names and
        alerting — that decides whether this warrants a warning.

        Raises:
            MissingTokenError: When no source supplied a token.
        """
        token = self.token()
        if not token:
            log.debug("No token available from source=%s", self._source())
            raise MissingTokenError()
        return token

    # -- claims access ---------------------------------------------------

    def claims(self) -> TokenClaims:
        """Unverified claims for the caller, empty when unauthenticated.

        Never raises — intended for logging, metrics and rate-limit keys.
        """
        return TokenClaims.from_token(self.token())

    # -- full context ----------------------------------------------------

    def resolve(self) -> AuthContext:
        """Resolve a complete :class:`AuthContext`.

        Raises:
            MissingTokenError: When no source supplied a token.
            InvalidTokenError: When verification is enabled and fails.
            ExpiredTokenError: When ``enforce_expiry`` is set and the token has
                expired.
        """
        token = self.require_token()

        if self.verify and self.verifier is not None:
            claims = self.verifier.verify(token)
        else:
            claims = TokenClaims.from_token(token)
            if self.enforce_expiry and claims.is_expired(leeway=self.leeway):
                raise ExpiredTokenError()

        return AuthContext(token=token, claims=claims, source=self._source())

    def try_resolve(self) -> Optional[AuthContext]:
        """Like :meth:`resolve`, but returns ``None`` instead of raising.

        Use on paths that must tolerate anonymous callers.  Verification and
        expiry failures are logged at debug level and also yield ``None``.
        """
        try:
            return self.resolve()
        except MissingTokenError:
            return None
        except Exception:
            log.debug("Token resolution failed", exc_info=True)
            return None

    # -- composition -----------------------------------------------------

    def with_provider(self, provider: TokenProvider) -> "TokenResolver":
        """A copy of this resolver bound to a different token source."""
        return TokenResolver(
            provider,
            verifier=self.verifier,
            verify=self.verify,
            enforce_expiry=self.enforce_expiry,
            leeway=self.leeway,
        )

    def _source(self) -> str:
        return (
            getattr(self.provider, "last_source", None)
            or getattr(self.provider, "source", None)
            or "unknown"
        )

    def __repr__(self) -> str:
        return (
            f"TokenResolver(provider={self.provider!r}, verify={self.verify}, "
            f"enforce_expiry={self.enforce_expiry})"
        )


__all__ = ["AuthContext", "TokenResolver", "TokenVerifier"]
