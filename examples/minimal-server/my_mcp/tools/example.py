"""
One example tool. Copy the shape, delete the body.

Note what the decorator gives you for free: sanitised parameter logging, timing,
error logging with a traceback, caller identity as structured fields, and the
``mcp_tool_*`` metrics. You do not log any of that yourself.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from my_mcp.auth import optional_token, require_token
from my_mcp.observability import tool_logger

log = logging.getLogger("my_mcp.tools")


@tool_logger("example_greet")
async def greet(name: str, loud: bool = False) -> Dict[str, Any]:
    """
    Greet someone. An unauthenticated read.

    Args:
        name: Who to greet.
        loud: Upper-case the greeting.

    Returns:
        A plain dict. Return dicts and lists, not custom objects — they have to
        cross the MCP boundary as JSON.
    """
    # optional_token() is None when the caller sent no token. Use it for reads
    # that should work either way; pass it upstream if you call an API that wants
    # the caller's own credentials rather than the server's.
    token: Optional[str] = optional_token()

    greeting = f"Hello, {name}!"
    return {
        "greeting": greeting.upper() if loud else greeting,
        "authenticated": token is not None,
    }


@tool_logger("example_whoami")
async def whoami() -> Dict[str, Any]:
    """
    Identify the caller. Requires a token.

    Raises:
        MissingTokenError: No usable token. It subclasses ``ValueError`` and the
            message is stable, so existing handlers keep working.
    """
    # require_token() raises rather than returning None, so protected tools do not
    # each re-implement the "is there a caller" check.
    token = require_token()

    # Claims for display only. This is an *unverified* decode — fine for a log
    # line or a greeting, never for an authorisation decision.
    from fabric_mcp_common.auth import TokenClaims

    claims = TokenClaims.from_token(token)
    return {
        "identity": claims.identity(),
        "email": claims.email or "",
        "project": claims.project_name or "",
        # Tells you whether a signature was actually checked. False unless you
        # configure a verifier — see the library's "Verify signatures" section.
        "verified": claims.verified,
    }


#: MCP tool name -> function. Named explicitly so the name clients see matches
#: the name @tool_logger records in logs and metrics; relying on the function
#: name lets those two drift apart.
TOOLS = {
    "example_greet": greet,
    "example_whoami": whoami,
}
