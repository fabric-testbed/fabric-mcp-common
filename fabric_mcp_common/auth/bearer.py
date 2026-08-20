"""
HTTP ``Authorization`` header parsing and token redaction.

Header lookup is case-insensitive, so plain dicts, ``dict(request.headers)``
and Starlette's own ``Headers`` object all work as input.
"""
from __future__ import annotations

from typing import Mapping, Optional, Tuple

#: Default header inspected for credentials.
AUTHORIZATION_HEADER = "authorization"

#: Default authentication scheme.
BEARER_SCHEME = "bearer"

#: Placeholder substituted for token material in logs.
REDACTED = "***"

#: Placeholder logged when no token was present at all.
NO_TOKEN = "<none>"

#: Returned by :func:`describe_authorization` — no ``Authorization`` header sent.
STATE_ABSENT = "absent"

#: Returned by :func:`describe_authorization` — header present but unusable.
STATE_MALFORMED = "malformed"

#: Returned by :func:`describe_authorization` — a token was extracted.
STATE_PRESENT = "present"


def get_header(
    headers: Optional[Mapping[str, str]],
    name: str = AUTHORIZATION_HEADER,
) -> Optional[str]:
    """Case-insensitively fetch a header value.

    Args:
        headers: Any mapping of header names to values, or ``None``.
        name: Header name to look up (compared case-insensitively).

    Returns:
        The header value, or ``None`` when absent.
    """
    if not headers:
        return None
    target = name.lower()
    try:
        items = headers.items()
    except AttributeError:
        return None
    for key, value in items:
        if isinstance(key, str) and key.lower() == target:
            return value
    return None


def parse_authorization(value: Optional[str]) -> Optional[Tuple[str, str]]:
    """Split an ``Authorization`` value into its scheme and credentials.

    Args:
        value: Raw header value, e.g. ``"Bearer eyJ..."``.

    Returns:
        ``(scheme_lowercased, credentials)`` when both parts are non-empty,
        otherwise ``None``.
    """
    if not value:
        return None
    stripped = value.strip()
    if " " not in stripped:
        return None
    scheme, _, credentials = stripped.partition(" ")
    credentials = credentials.strip()
    if not scheme or not credentials:
        return None
    return scheme.lower(), credentials


def extract_bearer_token(
    headers: Optional[Mapping[str, str]],
    *,
    header_name: str = AUTHORIZATION_HEADER,
    scheme: str = BEARER_SCHEME,
) -> Optional[str]:
    """Extract the credentials from a ``Bearer`` ``Authorization`` header.

    Args:
        headers: Mapping of HTTP headers (case-insensitive lookup).
        header_name: Header to read credentials from.
        scheme: Expected authentication scheme.

    Returns:
        The token string, or ``None`` if the header is absent, uses another
        scheme, or carries no credentials.

    Note:
        A header of exactly ``"Bearer "`` yields ``None`` here, where the
        original ``fabric_api_mcp`` helper returned an empty string.  Callers
        that tested falsiness are unaffected.
    """
    parsed = parse_authorization(get_header(headers, header_name))
    if parsed is None:
        return None
    got_scheme, credentials = parsed
    if got_scheme != scheme.lower():
        return None
    return credentials


def describe_authorization(
    headers: Optional[Mapping[str, str]],
    *,
    header_name: str = AUTHORIZATION_HEADER,
    scheme: str = BEARER_SCHEME,
) -> str:
    """Classify the ``Authorization`` header for metrics and diagnostics.

    Distinguishes "client sent nothing" from "client sent something broken",
    which is the signal security dashboards care about.

    Returns:
        :data:`STATE_ABSENT`, :data:`STATE_MALFORMED`, or :data:`STATE_PRESENT`.
    """
    raw = get_header(headers, header_name)
    if not raw or not raw.strip():
        return STATE_ABSENT
    if extract_bearer_token(headers, header_name=header_name, scheme=scheme) is None:
        return STATE_MALFORMED
    return STATE_PRESENT


def authorization_header(
    token: str,
    *,
    header_name: str = AUTHORIZATION_HEADER,
    scheme: str = "Bearer",
) -> dict:
    """Build an outbound ``Authorization`` header for *token*."""
    return {header_name: f"{scheme} {token}"}


def redact_token(token: Optional[str], *, keep: int = 0, placeholder: str = REDACTED) -> str:
    """Render a token safe for logging.

    Args:
        token: The token, or ``None``.
        keep: Number of trailing characters to retain, to correlate log lines
            without disclosing the credential.  Ignored for short tokens.
        placeholder: Text substituted for the redacted portion.

    Returns:
        :data:`NO_TOKEN` when *token* is empty, otherwise the placeholder
        optionally suffixed with the last ``keep`` characters.
    """
    if not token:
        return NO_TOKEN
    if keep > 0 and len(token) > keep * 2:
        return f"{placeholder}{token[-keep:]}"
    return placeholder


__all__ = [
    "AUTHORIZATION_HEADER",
    "BEARER_SCHEME",
    "NO_TOKEN",
    "REDACTED",
    "STATE_ABSENT",
    "STATE_MALFORMED",
    "STATE_PRESENT",
    "authorization_header",
    "describe_authorization",
    "extract_bearer_token",
    "get_header",
    "parse_authorization",
    "redact_token",
]
