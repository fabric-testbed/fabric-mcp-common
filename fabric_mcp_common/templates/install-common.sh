# shellcheck shell=bash
#
# Shared bootstrap helpers for FABRIC MCP server installers.
#
# Source this from an installer to get coloured logging, OS/package-manager
# detection, idempotent package installation, and Python 3.11+ discovery,
# instead of copying the same ~120 lines into every server's install.sh.
#
# Two ways to get this file:
#
#   1. Bootstrap installers (curl | bash), which run before any virtualenv
#      exists and so cannot import the Python package:
#
#        FMC_RAW="https://raw.githubusercontent.com/fabric-testbed/fabric-mcp-common/main"
#        curl -fsSL "$FMC_RAW/fabric_mcp_common/templates/install-common.sh" -o /tmp/install-common.sh
#        source /tmp/install-common.sh
#
#   2. Anything running after the package is installed:
#
#        source "$(python -c 'import fabric_mcp_common.templates as t; print(t.install_script_path())')"
#
# Contract for callers:
#   - Sets globals OS, PKG_MGR and PYTHON.
#   - Provides info/ok/warn/err/die, detect_os, pkg_install, ensure_command,
#     ensure_python, ensure_venv.
#   - Names match what fabric_api_mcp's install.sh used before extraction, so a
#     caller can source this and delete its local copies without further edits.
#
# Tunables (set before sourcing):
#   FMC_PYTHON_MIN_MINOR   Minimum Python 3.x minor version (default: 11)
#   FMC_PYTHON_CANDIDATES  Interpreter names to probe, most-preferred first

# Guard against double-sourcing: re-sourcing would be harmless, but this keeps
# the caller from paying for it and makes `source` idempotent.
if [[ -n "${_FMC_INSTALL_COMMON_SOURCED:-}" ]]; then
  # `|| true` looks unreachable to shellcheck (SC2317) and is, when this file is
  # sourced — which is the supported use. It matters only if someone *executes*
  # it, where `return` outside a function fails and would abort under `set -e`.
  # shellcheck disable=SC2317
  return 0 2>/dev/null || true
fi
_FMC_INSTALL_COMMON_SOURCED=1

: "${FMC_PYTHON_MIN_MINOR:=11}"
: "${FMC_PYTHON_CANDIDATES:=python3.14 python3.13 python3.12 python3.11 python3}"

# ----------------------- Logging -----------------------

info()  { printf '\033[1;34m[info]\033[0m  %s\n' "$*"; }
ok()    { printf '\033[1;32m[ok]\033[0m    %s\n' "$*"; }
warn()  { printf '\033[1;33m[warn]\033[0m  %s\n' "$*"; }
err()   { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; }
die()   { err "$@"; exit 1; }

# ----------------------- OS detection -----------------------

# Sets OS (macos|linux) and PKG_MGR (brew|apt|yum|dnf|unknown).
detect_os() {
  case "$(uname -s)" in
    Darwin*) OS="macos" ;;
    Linux*)  OS="linux" ;;
    *)       die "Unsupported OS: $(uname -s)" ;;
  esac

  if [[ "$OS" == "linux" ]]; then
    if command -v apt-get >/dev/null 2>&1; then
      PKG_MGR="apt"
    elif command -v yum >/dev/null 2>&1; then
      PKG_MGR="yum"
    elif command -v dnf >/dev/null 2>&1; then
      PKG_MGR="dnf"
    else
      PKG_MGR="unknown"
    fi
  else
    if command -v brew >/dev/null 2>&1; then
      PKG_MGR="brew"
    else
      PKG_MGR="unknown"
    fi
  fi

  info "Detected OS: $OS, package manager: $PKG_MGR"
}

# ----------------------- Package install helpers -----------------------

pkg_install() {
  local pkg="$1"
  case "$PKG_MGR" in
    brew) brew install "$pkg" ;;
    apt)  sudo apt-get update -qq && sudo apt-get install -y -qq "$pkg" ;;
    yum)  sudo yum install -y "$pkg" ;;
    dnf)  sudo dnf install -y "$pkg" ;;
    *)    die "Cannot install $pkg: no supported package manager found. Install it manually." ;;
  esac
}

# ensure_command <command> [package]
# Installs <package> (defaulting to <command>) unless <command> already exists.
ensure_command() {
  local cmd="$1"
  local pkg="${2:-$1}"
  if command -v "$cmd" >/dev/null 2>&1; then
    ok "$cmd is already installed"
  else
    info "Installing $pkg..."
    pkg_install "$pkg"
    if ! command -v "$cmd" >/dev/null 2>&1; then
      die "Failed to install $cmd. Please install it manually and re-run."
    fi
    ok "$cmd installed"
  fi
}

# ----------------------- Python helpers -----------------------

# Echo the first interpreter meeting the minimum minor version, else nothing.
# Factored out because the original install.sh ran this same probe twice —
# once before installing Python and once after.
_fmc_find_python() {
  local candidate ver
  # Re-default rather than trusting the global: an empty value would make the
  # `-ge` test below compare against 0, silently accepting any interpreter.
  local min="${FMC_PYTHON_MIN_MINOR:-11}"
  local candidates="${FMC_PYTHON_CANDIDATES:-python3.14 python3.13 python3.12 python3.11 python3}"
  for candidate in $candidates; do
    if command -v "$candidate" >/dev/null 2>&1; then
      ver="$("$candidate" -c 'import sys; print(sys.version_info.minor)' 2>/dev/null || echo 0)"
      if [[ "$ver" -ge "$min" ]]; then
        printf '%s\n' "$candidate"
        return 0
      fi
    fi
  done
  return 1
}

# Sets PYTHON to a 3.$FMC_PYTHON_MIN_MINOR+ interpreter, installing one if needed.
ensure_python() {
  local py
  if py="$(_fmc_find_python)"; then
    PYTHON="$py"
    ok "Python 3.$FMC_PYTHON_MIN_MINOR+ found: $PYTHON ($("$PYTHON" --version))"
    return
  fi

  info "Python 3.$FMC_PYTHON_MIN_MINOR+ not found, installing..."
  case "$PKG_MGR" in
    brew) brew install python@3.13 ;;
    apt)  sudo apt-get update -qq && sudo apt-get install -y -qq python3 python3-venv python3-pip ;;
    yum)  sudo yum install -y python3 python3-pip ;;
    dnf)  sudo dnf install -y python3 python3-pip ;;
    *)    die "Cannot install Python. Install Python 3.$FMC_PYTHON_MIN_MINOR+ manually and re-run." ;;
  esac

  if py="$(_fmc_find_python)"; then
    PYTHON="$py"
    ok "Python installed: $PYTHON ($("$PYTHON" --version))"
    return
  fi

  die "Could not find Python 3.$FMC_PYTHON_MIN_MINOR+ after installation. Install it manually and re-run."
}

# ensure_venv <dir>
# Creates a virtualenv at <dir> if absent, then upgrades pip inside it.
# Requires PYTHON, so call ensure_python first.
ensure_venv() {
  local venv_dir="$1"
  [[ -n "$venv_dir" ]] || die "ensure_venv: no directory given"
  [[ -n "${PYTHON:-}" ]] || die "ensure_venv: PYTHON is unset — call ensure_python first"

  if [[ -d "$venv_dir" ]]; then
    ok "Python venv already exists: $venv_dir"
  else
    info "Creating Python venv at $venv_dir..."
    "$PYTHON" -m venv "$venv_dir" || die "Failed to create venv at $venv_dir"
    ok "Venv created"
  fi

  "$venv_dir/bin/pip" install --quiet --upgrade pip
}
