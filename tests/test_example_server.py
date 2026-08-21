"""The bundled example must keep matching this library's API.

An example that has quietly rotted is worse than none: it is the first thing a new
server author copies. These tests resolve every ``fabric_mcp_common`` symbol the
example imports, so renaming or removing one here fails the library's own suite
rather than someone else's build.

Deliberately checks *symbol existence*, not source patterns — so it needs none of
the example's own dependencies (fastmcp, slowapi) and cannot drift into false
positives.
"""
from __future__ import annotations

import ast
import importlib
import pathlib

import pytest

EXAMPLE = pathlib.Path(__file__).resolve().parent.parent / "examples" / "minimal-server"

pytestmark = pytest.mark.skipif(
    not EXAMPLE.is_dir(), reason="examples/minimal-server not present"
)


def _example_sources():
    return sorted(EXAMPLE.rglob("*.py"))


def _library_imports(source: str):
    """(module, name) pairs the source imports from fabric_mcp_common."""
    pairs = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module.split(".")[0] == "fabric_mcp_common":
                for alias in node.names:
                    pairs.append((module, alias.name))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] == "fabric_mcp_common":
                    pairs.append((alias.name, None))
    return pairs


def test_the_example_imports_from_this_library():
    # Guards the guard: if the example stopped using fabric_mcp_common, the checks
    # below would pass vacuously.
    total = sum(len(_library_imports(p.read_text())) for p in _example_sources())
    assert total >= 8, f"example only imports {total} library symbols; is it still wired up?"


@pytest.mark.parametrize("path", _example_sources(), ids=lambda p: p.name)
def test_every_library_symbol_the_example_uses_exists(path):
    for module, name in _library_imports(path.read_text()):
        try:
            mod = importlib.import_module(module)
        except ImportError as exc:  # pragma: no cover - a real API break
            pytest.fail(f"{path.name} imports {module!r}, which does not import: {exc}")
        if name is not None:
            assert hasattr(mod, name), (
                f"{path.name} imports {name!r} from {module!r}, which no longer "
                "provides it — update the example alongside the API change"
            )


def test_the_example_advertises_the_safe_rate_limit_defaults():
    # The example exists largely to hand these defaults to the next server. If
    # rate_limit.py stops passing trusted_proxies, it is teaching the bypass.
    source = (EXAMPLE / "my_mcp" / "rate_limit.py").read_text()
    assert "trusted_proxies=" in source
    assert "require_verified" in source, (
        "rate_limit.py should explain require_verified even while relying on its "
        "default — it is the non-obvious half of the ordering"
    )


def test_the_example_pins_fastmcp_in_both_manifests():
    # The split that caused a production outage: the Dockerfile installs from
    # requirements.txt, `pip install .` uses pyproject.toml.
    for name in ("requirements.txt", "pyproject.toml"):
        text = (EXAMPLE / name).read_text()
        assert "fastmcp>=3,<4" in text, f"{name} does not cap fastmcp below 4.0"


def test_the_example_dockerfile_forbids_prereleases():
    directives = [
        line
        for line in (EXAMPLE / "Dockerfile").read_text().splitlines()
        if not line.lstrip().startswith("#")
    ]
    assert not [line for line in directives if "--prerelease=allow" in line]


def test_the_example_installer_sources_the_shared_library():
    # Rather than copying install-common.sh, which is the whole point of shipping
    # it as package data.
    install_sh = (EXAMPLE / "install.sh").read_text()
    from fabric_mcp_common.templates import INSTALL_SCRIPT_FILENAME

    assert INSTALL_SCRIPT_FILENAME in install_sh


class TestExampleRunsIfItsDepsArePresent:
    """Full import, when fastmcp and slowapi happen to be installed.

    Skipped in the library's own environment, which does not depend on them — the
    symbol checks above are what run there.
    """

    def test_modules_import(self):
        pytest.importorskip("fastmcp")
        pytest.importorskip("slowapi")
        import sys

        sys.path.insert(0, str(EXAMPLE))
        try:
            for name in ("my_mcp.config", "my_mcp.observability", "my_mcp.auth",
                         "my_mcp.rate_limit", "my_mcp.tools.example"):
                assert importlib.import_module(name) is not None
        finally:
            sys.path.remove(str(EXAMPLE))
