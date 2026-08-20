"""
JWT claim extraction for FABRIC identity tokens.

The functions here perform an **unverified** base64url decode of the JWT
payload.  That is the right tool for logging, metrics labels, rate-limit keys
and UI display, where the upstream FABRIC API is the component that actually
validates the token.  When the caller terminates authentication itself and
needs a cryptographic guarantee, use :mod:`fabric_mcp_common.auth.verify` instead.
"""
from __future__ import annotations

import base64
import binascii
import json
import logging
import time
from collections.abc import Mapping as _MappingABC
from typing import Any, Dict, Iterator, Mapping, Optional, Tuple

from fabric_mcp_common.auth.errors import InvalidTokenError

log = logging.getLogger("fabric.common.auth")

#: Claim names returned by the legacy ``decode_token_claims`` dict helper.
LEGACY_CLAIM_KEYS: Tuple[str, ...] = (
    "sub",
    "email",
    "name",
    "uuid",
    "project_name",
    "project_uuid",
)

#: Placeholder used when a token carries no usable identity claim.
ANONYMOUS = "anonymous"


def decode_payload(token: str, *, strict: bool = False) -> Dict[str, Any]:
    """Base64url-decode the payload (middle segment) of a JWT.

    No signature check is performed.

    Args:
        token: A compact JWS string (``header.payload.signature``).
        strict: Raise :class:`InvalidTokenError` on malformed input instead of
            returning an empty dict.

    Returns:
        The decoded payload, or ``{}`` when ``strict`` is false and the token
        cannot be decoded.

    Raises:
        InvalidTokenError: If ``strict`` is true and the token is malformed.
    """
    try:
        if not token or not isinstance(token, str):
            raise InvalidTokenError("Token is empty or not a string.")
        parts = token.split(".")
        if len(parts) != 3:
            raise InvalidTokenError(
                f"Expected a 3-segment compact JWS, got {len(parts)} segment(s)."
            )
        payload_b64 = parts[1]
        # base64url in JWTs is unpadded; restore padding before decoding.
        payload_b64 += "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        if not isinstance(payload, dict):
            raise InvalidTokenError("Token payload is not a JSON object.")
        return payload
    except InvalidTokenError:
        if strict:
            raise
        log.debug("Failed to decode JWT payload", exc_info=True)
        return {}
    except (ValueError, binascii.Error, UnicodeDecodeError) as e:
        if strict:
            raise InvalidTokenError(f"Failed to decode JWT payload: {e}") from e
        log.debug("Failed to decode JWT payload", exc_info=True)
        return {}


def _derive(payload: Mapping[str, Any]) -> Dict[str, Any]:
    """Compute the convenience claims FABRIC callers expect from a payload."""
    derived: Dict[str, Any] = {}
    projects = payload.get("projects")
    if isinstance(projects, list) and projects:
        first = projects[0]
        if isinstance(first, dict):
            if "name" in first:
                derived["project_name"] = first["name"]
            if "uuid" in first:
                derived["project_uuid"] = first["uuid"]
    return derived


class TokenClaims(_MappingABC):
    """Read-only view over a decoded FABRIC token payload.

    Behaves as a ``Mapping``, so ``claims.get("sub")`` and ``"email" in claims``
    work exactly as they did against the plain dicts this class replaces.  An
    undecodable token yields an empty, falsy instance rather than raising, which
    keeps logging and metrics paths free of error handling.

    Beyond the raw payload keys, ``project_name`` and ``project_uuid`` are
    derived from the first entry of the ``projects`` claim.
    """

    __slots__ = ("_payload", "_derived", "_verified")

    def __init__(
        self,
        payload: Optional[Mapping[str, Any]] = None,
        *,
        verified: bool = False,
    ) -> None:
        """
        Args:
            payload: Decoded JWT payload.  ``None`` produces empty claims.
            verified: Whether the payload came from a signature-verified decode.
        """
        self._payload: Dict[str, Any] = dict(payload or {})
        self._derived: Dict[str, Any] = _derive(self._payload)
        self._verified = bool(verified)

    # -- constructors ----------------------------------------------------

    @classmethod
    def from_token(cls, token: Optional[str], *, strict: bool = False) -> "TokenClaims":
        """Build claims from a raw JWT via an unverified payload decode.

        Args:
            token: Compact JWS string, or ``None``.
            strict: Propagate :class:`InvalidTokenError` on malformed tokens.
        """
        if token is None:
            if strict:
                raise InvalidTokenError("Token is empty or not a string.")
            return cls()
        return cls(decode_payload(token, strict=strict))

    @classmethod
    def empty(cls) -> "TokenClaims":
        """An empty (falsy) claim set, for unauthenticated requests."""
        return cls()

    # -- Mapping protocol ------------------------------------------------

    def __getitem__(self, key: str) -> Any:
        if key in self._derived:
            return self._derived[key]
        return self._payload[key]

    def __iter__(self) -> Iterator[str]:
        seen = set(self._payload)
        yield from self._payload
        for key in self._derived:
            if key not in seen:
                yield key

    def __len__(self) -> int:
        return len(self._payload) + sum(1 for k in self._derived if k not in self._payload)

    # -- identity claims -------------------------------------------------

    @property
    def sub(self) -> Optional[str]:
        """OIDC subject identifier."""
        return self._payload.get("sub")

    @property
    def email(self) -> Optional[str]:
        """User email address."""
        return self._payload.get("email")

    @property
    def name(self) -> Optional[str]:
        """User display name."""
        return self._payload.get("name")

    @property
    def uuid(self) -> Optional[str]:
        """FABRIC user UUID."""
        return self._payload.get("uuid")

    @property
    def projects(self) -> Tuple[Dict[str, Any], ...]:
        """All projects carried by the token."""
        projects = self._payload.get("projects")
        if isinstance(projects, list):
            return tuple(p for p in projects if isinstance(p, dict))
        return ()

    @property
    def project_name(self) -> Optional[str]:
        """Name of the token's first project, if any."""
        return self._derived.get("project_name")

    @property
    def project_uuid(self) -> Optional[str]:
        """UUID of the token's first project, if any."""
        return self._derived.get("project_uuid")

    # -- lifetime claims -------------------------------------------------

    @property
    def exp(self) -> Optional[int]:
        """Expiry as a POSIX timestamp, if present."""
        return _as_int(self._payload.get("exp"))

    @property
    def iat(self) -> Optional[int]:
        """Issued-at as a POSIX timestamp, if present."""
        return _as_int(self._payload.get("iat"))

    @property
    def iss(self) -> Optional[str]:
        """Token issuer."""
        return self._payload.get("iss")

    @property
    def aud(self) -> Optional[Any]:
        """Token audience (string or list, per the JWT spec)."""
        return self._payload.get("aud")

    # -- derived helpers -------------------------------------------------

    @property
    def verified(self) -> bool:
        """True when these claims came from a signature-verified decode."""
        return self._verified

    @property
    def raw(self) -> Dict[str, Any]:
        """A copy of the decoded payload, without derived claims."""
        return dict(self._payload)

    def is_expired(self, *, leeway: float = 0.0, now: Optional[float] = None) -> bool:
        """Whether the token's ``exp`` claim is in the past.

        Args:
            leeway: Seconds of clock skew to tolerate.  A token counts as
                expired only once ``exp + leeway`` has passed.
            now: Override the current POSIX time (for testing).

        Returns:
            False when no ``exp`` claim is present — absence of an expiry is
            not evidence of expiry.
        """
        exp = self.exp
        if exp is None:
            return False
        return exp + leeway < (time.time() if now is None else now)

    def expires_in(self, *, now: Optional[float] = None) -> Optional[float]:
        """Seconds until expiry (negative if already expired), or ``None``."""
        exp = self.exp
        if exp is None:
            return None
        return exp - (time.time() if now is None else now)

    def identity(self, default: str = ANONYMOUS) -> str:
        """Best available human-facing identifier for logs and metrics.

        Prefers ``email``, then ``name``, ``sub``, ``uuid``, then ``default``.
        """
        for value in (self.email, self.name, self.sub, self.uuid):
            if value:
                return str(value)
        return default

    def to_dict(self, *, include_derived: bool = True) -> Dict[str, Any]:
        """Serialize claims to a plain dict.

        Args:
            include_derived: Include ``project_name`` / ``project_uuid``.
        """
        out = dict(self._payload)
        if include_derived:
            out.update(self._derived)
        return out

    def legacy_dict(self) -> Dict[str, Any]:
        """The exact claim subset returned by the pre-extraction helper.

        Only :data:`LEGACY_CLAIM_KEYS` that are actually present are included.
        """
        merged = self.to_dict()
        return {k: merged[k] for k in LEGACY_CLAIM_KEYS if k in merged}

    # -- dunders ---------------------------------------------------------

    def __eq__(self, other: object) -> bool:
        if isinstance(other, TokenClaims):
            return self._payload == other._payload
        if isinstance(other, _MappingABC):
            return self.to_dict() == dict(other)
        return NotImplemented

    def __ne__(self, other: object) -> bool:
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self) -> int:  # pragma: no cover - identity-based, matches Mapping semantics
        return id(self)

    def __repr__(self) -> str:
        return (
            f"TokenClaims(identity={self.identity()!r}, "
            f"project={self.project_name!r}, verified={self._verified})"
        )


def _as_int(value: Any) -> Optional[int]:
    """Coerce a numeric claim to int, returning None when it isn't numeric."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def decode_token_claims(token: str) -> Dict[str, Any]:
    """Decode a JWT into the legacy identity-claim dict.

    Compatibility shim for the original ``fabric_api_mcp.auth.token``
    implementation: returns only :data:`LEGACY_CLAIM_KEYS` that are present,
    and ``{}`` on any failure.  New code should prefer
    :meth:`TokenClaims.from_token`, which also exposes ``exp`` and the full
    project list.

    Args:
        token: A JWT string.

    Returns:
        Dict with ``sub``, ``email``, ``name``, ``uuid``, ``project_name`` and
        ``project_uuid`` claims where present, or ``{}`` on failure.
    """
    return TokenClaims.from_token(token).legacy_dict()


__all__ = [
    "ANONYMOUS",
    "LEGACY_CLAIM_KEYS",
    "TokenClaims",
    "decode_payload",
    "decode_token_claims",
]
