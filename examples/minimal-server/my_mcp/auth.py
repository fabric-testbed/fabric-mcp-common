"""
The server's shared token resolver.

One resolver, built from the deployment mode, used by every protected path:

* **server / HTTP** — the token comes from the request's ``Authorization: Bearer``
  header and nothing else.
* **local / stdio** — the token comes from the file named by
  ``FABRIC_TOKEN_LOCATION``.

``allow_header_in_local_mode=False`` is the security-relevant argument. Leaving it
at the library default (True) would let a caller-supplied header be honoured in
local mode, which means a local token file could be bypassed by whoever can reach
the process.
"""
from __future__ import annotations

import logging
from typing import Optional

from fabric_mcp_common.auth import MissingTokenError
from fabric_mcp_common.integrations.fastmcp import build_resolver, current_token

from my_mcp.config import config

log = logging.getLogger("my_mcp.auth")

#: Resolves per call, so a rotated token file or a new request's header is always
#: picked up rather than captured once at import.
resolver = build_resolver(
    local_mode=config.local_mode,
    allow_header_in_local_mode=False,
)


def require_token() -> str:
    """The caller's token, or raise.

    Raises:
        MissingTokenError: No usable token. Subclasses ``ValueError``, and the
            message is stable, so ``except ValueError`` handlers and
            ``{"error", "details"}`` payloads keep working.
    """
    try:
        return resolver.require_token()
    except MissingTokenError:
        log.warning("Missing Authorization header on protected call")
        raise


def optional_token() -> Optional[str]:
    """The in-flight request's bearer token, or ``None``.

    Header-only by design. Use this for reads that should work unauthenticated;
    use :func:`require_token` where a caller must be identified.
    """
    return current_token()


__all__ = ["optional_token", "require_token", "resolver"]
