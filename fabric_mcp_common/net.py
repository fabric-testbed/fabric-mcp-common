"""
Header-level network helpers shared by the framework adapters.

Kept separate from :mod:`fabric_mcp_common.auth.bearer` (which is about credentials)
and from the adapters (which are about request objects), so that both the
Starlette adapter — which has a request — and the FastMCP adapter — which only
ever sees a header mapping — resolve the client IP the same way.
"""
from __future__ import annotations

import ipaddress
from typing import Iterable, Mapping, Optional, Sequence

#: Headers consulted, in order, for the real client IP behind a proxy.
#:
#: Suitable for logs and metric labels. **Not** for security decisions: see
#: :data:`OVERWRITING_FORWARDED_HEADER` for why ``x-forwarded-for`` cannot be
#: trusted even on a trusted hop.
DEFAULT_FORWARDED_HEADERS: Sequence[str] = ("x-real-ip", "x-forwarded-for")

#: The one forwarded header a proxy typically *overwrites* rather than appends
#: to, which is what makes it usable for a security decision.
#:
#: nginx sets ``X-Real-IP`` from ``$remote_addr`` — a replacement — but sets
#: ``X-Forwarded-For`` from ``$proxy_add_x_forwarded_for``, which **appends** to
#: whatever the client sent.  So the left-most ``X-Forwarded-For`` entry is
#: caller-controlled even when the request genuinely came through the proxy,
#: while ``X-Real-IP`` reflects the proxy's own peer.
OVERWRITING_FORWARDED_HEADER = "x-real-ip"

#: Value reported when the client IP cannot be determined.
UNKNOWN_IP = "unknown"


def peer_in_networks(host: Optional[str], networks: Iterable[str]) -> bool:
    """Whether *host* falls inside any of *networks*.

    The socket peer is the one address a remote caller cannot forge, so matching
    it against an explicit list is what makes a forwarded header believable.

    Args:
        host: Peer address, e.g. Starlette's ``request.client.host``.  ``None``,
            empty and unparseable values are not trusted.
        networks: CIDR strings or bare addresses.  Malformed entries are skipped
            rather than raising, so one bad config value cannot take a server
            down; pre-validate with :func:`invalid_networks` to report them.

    Returns:
        True only when *host* parses and lies inside one of *networks*.
    """
    if not host:
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    for entry in networks:
        try:
            if address in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            continue
    return False


def invalid_networks(networks: Iterable[str]) -> list:
    """Entries of *networks* that are not parseable CIDRs, for startup logging."""
    bad = []
    for entry in networks:
        try:
            ipaddress.ip_network(entry, strict=False)
        except ValueError:
            bad.append(entry)
    return bad


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


__all__ = [
    "DEFAULT_FORWARDED_HEADERS",
    "OVERWRITING_FORWARDED_HEADER",
    "UNKNOWN_IP",
    "client_ip_from_headers",
    "invalid_networks",
    "peer_in_networks",
]
