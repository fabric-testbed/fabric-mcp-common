"""Package surface: subpackage laziness, dependency isolation, error contract."""
from __future__ import annotations

import importlib
import sys

import pytest

import fabric_mcp_common as pkg
from fabric_mcp_common.auth.errors import (
    MISSING_TOKEN_MESSAGE,
    AuthError,
    ExpiredTokenError,
    InvalidTokenError,
    MissingTokenError,
    TokenSourceError,
    VerificationUnavailableError,
)

SUBPACKAGES = (
    "fabric_mcp_common.auth",
    "fabric_mcp_common.logging",
    "fabric_mcp_common.metrics",
    "fabric_mcp_common.integrations.fastmcp",
    "fabric_mcp_common.integrations.starlette",
)


def _unload(prefix: str = "fabric_mcp_common") -> None:
    """Drop the package from sys.modules so import side effects can be observed."""
    for name in [n for n in sys.modules if n == prefix or n.startswith(prefix + ".")]:
        del sys.modules[name]


class TestTopLevel:
    def test_version_is_exposed(self):
        assert pkg.__version__.count(".") == 2

    def test_logger_namespace_is_a_single_parent(self):
        # One name must cover every subpackage, present and future.
        assert pkg.LOGGER_NAMESPACE == "fabric.common"

    def test_importing_the_root_pulls_in_no_subpackages(self):
        _unload()
        importlib.import_module("fabric_mcp_common")
        assert [s for s in SUBPACKAGES if s in sys.modules] == []

    def test_root_has_no_third_party_imports(self):
        _unload()
        blocked = ("fastmcp", "starlette", "fss_utils", "jwt", "requests", "prometheus_client")
        placed = [b for b in blocked if b not in sys.modules]
        for b in placed:
            sys.modules[b] = None
        try:
            importlib.import_module("fabric_mcp_common")
        finally:
            for b in placed:
                if sys.modules.get(b) is None:
                    del sys.modules[b]


class TestAuthSubpackage:
    def test_all_names_are_importable(self):
        auth = importlib.import_module("fabric_mcp_common.auth")
        assert [n for n in auth.__all__ if not hasattr(auth, n)] == []

    def test_verification_api_is_lazy(self):
        _unload()
        auth = importlib.import_module("fabric_mcp_common.auth")
        assert "fabric_mcp_common.auth.verify" not in sys.modules
        assert auth.CredMgrVerifier is not None
        assert "fabric_mcp_common.auth.verify" in sys.modules

    @pytest.mark.parametrize("name", ["CredMgrVerifier", "verify_token", "credmgr_jwks_url"])
    def test_verification_names_reachable_from_auth(self, name):
        auth = importlib.import_module("fabric_mcp_common.auth")
        assert getattr(auth, name) is not None

    def test_unknown_attributes_still_raise(self):
        auth = importlib.import_module("fabric_mcp_common.auth")
        with pytest.raises(AttributeError):
            auth.does_not_exist

    def test_auth_does_not_import_integrations_or_metrics(self):
        _unload()
        importlib.import_module("fabric_mcp_common.auth")
        leaked = [
            s for s in SUBPACKAGES
            if s in sys.modules and s != "fabric_mcp_common.auth"
        ]
        assert leaked == []

    def test_auth_needs_no_third_party_packages(self):
        _unload()
        blocked = ("fastmcp", "starlette", "fss_utils", "jwt", "requests", "prometheus_client")
        placed = [b for b in blocked if b not in sys.modules]
        for b in placed:
            sys.modules[b] = None
        try:
            importlib.import_module("fabric_mcp_common.auth")
        finally:
            for b in placed:
                if sys.modules.get(b) is None:
                    del sys.modules[b]


class TestLoggingSubpackage:
    def test_needs_no_third_party_packages(self):
        _unload()
        blocked = ("fastmcp", "starlette", "fss_utils", "jwt", "requests", "prometheus_client")
        placed = [b for b in blocked if b not in sys.modules]
        for b in placed:
            sys.modules[b] = None
        try:
            importlib.import_module("fabric_mcp_common.logging")
        finally:
            for b in placed:
                if sys.modules.get(b) is None:
                    del sys.modules[b]

    def test_does_not_import_metrics(self):
        # The tool decorator resolves the metrics sink lazily, so a server that
        # logs but does not scrape never pays for prometheus-client.
        _unload()
        importlib.import_module("fabric_mcp_common.logging")
        assert "fabric_mcp_common.metrics" not in sys.modules

    def test_all_names_are_importable(self):
        mod = importlib.import_module("fabric_mcp_common.logging")
        assert [n for n in mod.__all__ if not hasattr(mod, n)] == []

    def test_stdlib_logging_is_not_shadowed_inside_the_package(self):
        import fabric_mcp_common.logging.config as cfg

        assert cfg.logging.__name__ == "logging"
        assert hasattr(cfg.logging, "getLogger")


class TestErrorContract:
    @pytest.mark.parametrize(
        "exc_type",
        [
            AuthError,
            MissingTokenError,
            InvalidTokenError,
            ExpiredTokenError,
            TokenSourceError,
            VerificationUnavailableError,
        ],
    )
    def test_every_error_is_a_valueerror(self, exc_type):
        assert issubclass(exc_type, ValueError)

    @pytest.mark.parametrize(
        "exc_type",
        [MissingTokenError, InvalidTokenError, ExpiredTokenError, TokenSourceError],
    )
    def test_default_details_are_populated(self, exc_type):
        exc = exc_type()
        assert exc.details
        assert str(exc) == exc.details

    def test_custom_details_win(self):
        assert MissingTokenError("custom").details == "custom"

    def test_missing_token_message_is_unchanged_from_the_original(self):
        assert MissingTokenError().details == MISSING_TOKEN_MESSAGE
        assert "Authentication Required" in MISSING_TOKEN_MESSAGE

    def test_to_dict_matches_the_json_error_contract(self):
        assert MissingTokenError("why").to_dict() == {
            "error": "unauthorized",
            "details": "why",
        }

    def test_expired_is_a_kind_of_invalid(self):
        assert issubclass(ExpiredTokenError, InvalidTokenError)

    def test_key_fetch_failures_are_reported_as_server_errors(self):
        assert VerificationUnavailableError().to_dict()["error"] == "server_error"

    def test_base_error_accepts_no_details(self):
        assert AuthError().details == AuthError.default_details
