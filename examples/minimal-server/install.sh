#!/usr/bin/env bash
set -euo pipefail

# ===================================================================
# install.sh — bootstrap installer for my-mcp
#
#   curl -fsSL https://raw.githubusercontent.com/<org>/<repo>/main/install.sh | bash
# ===================================================================

VENV_DIR="${VENV_DIR:-$HOME/.local/share/my-mcp/venv}"

# ----------------------- Shared bootstrap helpers -----------------------
#
# Logging, OS/package-manager detection, package installation, Python discovery
# and venv creation live in fabric_mcp_common — not copied in here.
#
# This runs before any virtualenv exists, so the library cannot be imported to
# locate the file; it is fetched over HTTPS. Point FABRIC_MCP_COMMON_INSTALL_SH
# at a local file for offline installs or to test an unreleased change.

FMC_RAW="${FABRIC_MCP_COMMON_RAW:-https://raw.githubusercontent.com/fabric-testbed/fabric-mcp-common/main}"
FMC_INSTALL_SH="${FABRIC_MCP_COMMON_INSTALL_SH:-}"
FMC_TMP=""

# Cannot use err()/die() yet — they come from the file being fetched.
_bootstrap_die() { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

if [[ -z "$FMC_INSTALL_SH" ]]; then
  FMC_TMP="$(mktemp -t fabric-mcp-install-common.XXXXXX)" \
    || _bootstrap_die "Could not create a temporary file."
  FMC_URL="$FMC_RAW/fabric_mcp_common/templates/install-common.sh"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$FMC_URL" -o "$FMC_TMP" || _bootstrap_die "Could not download $FMC_URL"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$FMC_TMP" "$FMC_URL" || _bootstrap_die "Could not download $FMC_URL"
  else
    _bootstrap_die "Neither curl nor wget is available; install one and re-run."
  fi
  FMC_INSTALL_SH="$FMC_TMP"
fi

[[ -s "$FMC_INSTALL_SH" ]] || _bootstrap_die "Installer helpers missing or empty: $FMC_INSTALL_SH"

# shellcheck source=/dev/null
source "$FMC_INSTALL_SH" || _bootstrap_die "Could not load $FMC_INSTALL_SH"
[[ -n "$FMC_TMP" ]] && rm -f "$FMC_TMP"

# Fail here with a clear message if upstream drifted, rather than as
# "command not found" halfway through an install.
for _fn in info ok warn err die detect_os ensure_command ensure_python ensure_venv; do
  declare -F "$_fn" >/dev/null \
    || _bootstrap_die "Installer helpers did not define '$_fn' — version mismatch?"
done
unset _fn

# ----------------------- Install -----------------------

main() {
  detect_os                     # sets OS, PKG_MGR
  ensure_python                 # sets PYTHON to a 3.11+ interpreter
  ensure_venv "$VENV_DIR"       # creates the venv, upgrades pip inside it

  info "Installing my_mcp..."
  "$VENV_DIR/bin/pip" install --quiet .
  ok "Installed. Run: $VENV_DIR/bin/my-mcp"
}

main "$@"
