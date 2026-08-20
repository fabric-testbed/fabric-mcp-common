"""
Exception hierarchy for FABRIC token authentication.

All errors derive from :class:`AuthError`, which itself derives from
``ValueError``.  Deriving from ``ValueError`` is deliberate: the FABRIC MCP
servers this library was extracted from raise ``ValueError`` on missing or
invalid tokens, and MCP frameworks surface that as a tool error.  Existing
``except ValueError`` handlers therefore keep working after migration, while
new code can catch the precise type.

Every error carries an ``error_type`` matching the FABRIC MCP error contract
(``{"error": "<type>", "details": "<reason>"}``) and can serialize itself with
:meth:`AuthError.to_dict`.
"""
from __future__ import annotations

from typing import Dict, Optional

MISSING_TOKEN_MESSAGE = "Authentication Required: Missing or invalid Authorization Bearer token."


class AuthError(ValueError):
    """Base class for all authentication failures.

    Args:
        details: Human readable reason.  Falls back to the subclass default.
    """

    #: Error type reported in the JSON error contract.
    error_type: str = "unauthorized"

    #: Message used when no explicit ``details`` are supplied.
    default_details: str = "Authentication failed."

    def __init__(self, details: Optional[str] = None) -> None:
        self.details = details or self.default_details
        super().__init__(self.details)

    def to_dict(self) -> Dict[str, str]:
        """Serialize to the FABRIC MCP error contract."""
        return {"error": self.error_type, "details": self.details}


class MissingTokenError(AuthError):
    """No token could be resolved from any configured source."""

    default_details = MISSING_TOKEN_MESSAGE


class InvalidTokenError(AuthError):
    """A token was supplied but could not be parsed or verified."""

    default_details = "Authentication Required: Token is malformed or could not be verified."


class ExpiredTokenError(InvalidTokenError):
    """A token was supplied and parsed, but has expired."""

    default_details = "Authentication Required: Token has expired."


class TokenSourceError(AuthError):
    """A token source (file, environment variable) is misconfigured or unreadable.

    Distinct from :class:`MissingTokenError`: the source was *supposed* to
    provide a token and failed, rather than simply being absent.
    """

    default_details = "Token source is unavailable."


class VerificationUnavailableError(AuthError):
    """Signature verification was requested but its dependencies are missing."""

    error_type = "server_error"
    default_details = (
        "Token verification requires the optional 'verify' extra: "
        "pip install fabric-mcp-common[verify]"
    )


__all__ = [
    "MISSING_TOKEN_MESSAGE",
    "AuthError",
    "MissingTokenError",
    "InvalidTokenError",
    "ExpiredTokenError",
    "TokenSourceError",
    "VerificationUnavailableError",
]
