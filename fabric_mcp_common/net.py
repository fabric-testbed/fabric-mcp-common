"""
Header-level network helpers shared by the framework adapters.

Kept separate from :mod:`fabric_mcp_common.auth.bearer` (which is about credentials)
and from the adapters (which are about request objects), so that both the
Starlette adapter — which has a request — and the FastMCP adapter — which only
ever sees a header mapping — resolve the client IP the same way.
"""
from __future__ import annotations

from typing import Mapping, Optional, Sequence

#: Headers consulted, in order, for the real client IP behind a proxy.
DEFAULT_FORWARDED_HEADERS: Sequence[str] = ("x-real-ip", "x-forwarded-for")

#: Value reported when the client IP cannot be determined.
UNKNOWN_IP = "unknown"


def client_ip_from_headers(
    headers: Optional[Mapping[str, str]],
    *,
    forwarded_headers: Sequence[str] = DEFAULT_FORWARDED_HEADERS,
) -> Optional[str]:
    """Resolve the client IP from reverse-proxy headers.

    Checks each of *forwarded_headers* in order, taking the left-most entry of a
    comma-separated list.

    Args:
        headers: Header mapping (case-insensitive lookup), or ``None``.
        forwarded_headers: Header names to consult, highest precedence first.

    Returns:
        The IP, or ``None`` when no header identified one.

    Warning:
        These headers are client-supplied and trivially spoofed unless a trusted
        proxy overwrites them.  Only meaningful when the app sits behind one.
    """
    if not headers:
        return None
    try:
        lowered = {k.lower(): v for k, v in headers.items() if isinstance(k, str)}
    except AttributeError:
        return None

    for name in forwarded_headers:
        value = lowered.get(name.lower())
        if not value:
            continue
        first = str(value).split(",")[0].strip()
        if first:
            return first
    return None


__all__ = ["DEFAULT_FORWARDED_HEADERS", "UNKNOWN_IP", "client_ip_from_headers"]
