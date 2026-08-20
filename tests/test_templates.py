"""Installer templates: package data resolves, and the shell library is sound."""
from __future__ import annotations

import shutil
import subprocess

import pytest

from fabric_mcp_common.templates import (
    INSTALL_SCRIPT_FILENAME,
    INSTALL_SCRIPT_RAW_URL,
    install_script_path,
    install_script_url,
)

BASH = shutil.which("bash")

#: Names the shell library promises callers. fabric_api_mcp's install.sh sources
#: this and relies on every one of them, so a rename here breaks it silently.
EXPORTED_FUNCTIONS = (
    "info",
    "ok",
    "warn",
    "err",
    "die",
    "detect_os",
    "pkg_install",
    "ensure_command",
    "ensure_python",
    "ensure_venv",
)


class TestPackageData:
    def test_script_ships_and_is_readable(self):
        path = install_script_path()
        assert path.is_file(), f"{path} missing — is it excluded from package data?"
        assert path.read_text().lstrip().startswith("# shellcheck shell=bash")

    def test_path_uses_the_declared_filename(self):
        assert install_script_path().name == INSTALL_SCRIPT_FILENAME

    def test_raw_url_points_at_the_same_filename(self):
        # A drifting URL would 404 only at bootstrap time, where it is hardest
        # to debug, so pin the two together here.
        assert install_script_url() == INSTALL_SCRIPT_RAW_URL
        assert INSTALL_SCRIPT_RAW_URL.endswith(f"/{INSTALL_SCRIPT_FILENAME}")
        assert INSTALL_SCRIPT_RAW_URL.startswith("https://")


@pytest.mark.skipif(BASH is None, reason="bash not available")
class TestShellLibrary:
    def test_parses_under_bash(self):
        result = subprocess.run(
            [BASH, "-n", str(install_script_path())],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr

    @pytest.mark.parametrize("func", EXPORTED_FUNCTIONS)
    def test_sourcing_defines(self, func):
        script = f'source "{install_script_path()}"; declare -F {func} >/dev/null'
        result = subprocess.run([BASH, "-c", script], capture_output=True, text=True)
        assert result.returncode == 0, f"{func} not defined after sourcing"

    def test_sourcing_twice_is_a_noop(self):
        script = (
            f'source "{install_script_path()}"; '
            f'source "{install_script_path()}"; '
            'echo "$_FMC_INSTALL_COMMON_SOURCED"'
        )
        result = subprocess.run([BASH, "-c", script], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "1"

    def test_detect_os_sets_its_globals(self):
        script = f'source "{install_script_path()}"; detect_os >/dev/null; echo "$OS/$PKG_MGR"'
        result = subprocess.run([BASH, "-c", script], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        os_name, _, pkg_mgr = result.stdout.strip().partition("/")
        assert os_name in {"macos", "linux"}
        assert pkg_mgr in {"brew", "apt", "yum", "dnf", "unknown"}

    def test_ensure_python_finds_an_interpreter(self):
        script = f'source "{install_script_path()}"; detect_os >/dev/null; ensure_python >/dev/null; echo "$PYTHON"'
        result = subprocess.run([BASH, "-c", script], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip().startswith("python3")

    def test_min_version_is_tunable(self):
        # An absurd floor must fail rather than silently accept an old
        # interpreter; this is the knob downstream installers rely on.
        # export, not a `VAR=x source` prefix: that binding is discarded when
        # source returns, which is how the empty-value bug below was found.
        script = (
            f'export FMC_PYTHON_MIN_MINOR=99; source "{install_script_path()}"; '
            "_fmc_find_python"
        )
        result = subprocess.run([BASH, "-c", script], capture_output=True, text=True)
        assert result.returncode != 0
        assert result.stdout.strip() == ""

    def test_empty_min_version_does_not_accept_anything(self):
        # An empty floor must fall back to the default, not compare against 0
        # and pass every interpreter.
        script = (
            f'source "{install_script_path()}"; FMC_PYTHON_MIN_MINOR=""; '
            "_fmc_find_python"
        )
        result = subprocess.run([BASH, "-c", script], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip().startswith("python3")

    def test_ensure_venv_requires_python_to_be_set(self):
        script = f'source "{install_script_path()}"; ensure_venv /tmp/does-not-matter'
        result = subprocess.run([BASH, "-c", script], capture_output=True, text=True)
        assert result.returncode != 0
        assert "PYTHON is unset" in result.stderr

    def test_ensure_venv_rejects_a_missing_directory_argument(self):
        script = f'source "{install_script_path()}"; ensure_venv'
        result = subprocess.run([BASH, "-c", script], capture_output=True, text=True)
        assert result.returncode != 0
        assert "no directory given" in result.stderr

    def test_ensure_venv_creates_and_is_idempotent(self, tmp_path):
        venv = tmp_path / "venv"
        script = (
            f'source "{install_script_path()}"; detect_os >/dev/null; '
            f'ensure_python >/dev/null; ensure_venv "{venv}" >/dev/null; '
            f'ensure_venv "{venv}" >/dev/null; echo done'
        )
        result = subprocess.run([BASH, "-c", script], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        assert (venv / "bin" / "python").exists()
