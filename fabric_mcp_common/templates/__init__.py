"""
Reusable installer templates for FABRIC MCP servers.

``install-common.sh`` holds the boilerplate every server's ``install.sh`` needs
— coloured logging, OS and package-manager detection, idempotent package
installation, Python 3.11+ discovery, virtualenv creation — so each server does
not carry its own copy.

Bootstrap installers run before any virtualenv exists, so they cannot import
this package to find the file; they fetch it over HTTPS instead::

    curl -fsSL "$(python -c 'import fabric_mcp_common.templates as t; print(t.install_script_url())')"

which is only useful once the package is installed.  For the genuine
cold-start case, hard-code the raw URL (see :data:`INSTALL_SCRIPT_RAW_URL`) —
the point of shipping the file here as well is that anything running *after*
installation can locate it without a network round-trip.
"""
from __future__ import annotations

import pathlib

#: Filename of the bundled shell library, inside ``fabric_mcp_common/templates/``.
INSTALL_SCRIPT_FILENAME = "install-common.sh"

#: Canonical raw URL, for installers that must fetch before this package exists.
INSTALL_SCRIPT_RAW_URL = (
    "https://raw.githubusercontent.com/fabric-testbed/fabric-mcp-common/main/"
    f"fabric_mcp_common/templates/{INSTALL_SCRIPT_FILENAME}"
)


def install_script_path() -> pathlib.Path:
    """Filesystem path to the bundled installer shell library.

    Ships as package data, so it resolves from an installed wheel::

        source "$(python -c 'import fabric_mcp_common.templates as t; print(t.install_script_path())')"
    """
    return pathlib.Path(__file__).resolve().parent / INSTALL_SCRIPT_FILENAME


def install_script_url() -> str:
    """Canonical raw URL of the installer shell library."""
    return INSTALL_SCRIPT_RAW_URL


__all__ = [
    "INSTALL_SCRIPT_FILENAME",
    "INSTALL_SCRIPT_RAW_URL",
    "install_script_path",
    "install_script_url",
]
