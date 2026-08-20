"""Tests for the FastMCP adapter, with the framework stubbed out."""
from __future__ import annotations

import json
import sys
import types

import pytest

from fabric_mcp_common.auth.errors import MissingTokenError
from fabric_mcp_common.integrations import fastmcp as adapter
from fabric_mcp_common.auth.providers import TOKEN_ENV, TOKEN_LOCATION_ENV


@pytest.fixture
def fake_fastmcp(monkeypatch):
    """Install a stub ``fastmcp.server.dependencies`` module.

    Returns a control dict: set ``headers`` to what the request carries, or
    ``raise_`` to an exception to simulate being outside a request scope.
    """
    control = {"headers": {}, "raise_": None, "include_seen": []}

    def get_http_headers(include=None):
        control["include_seen"].append(include)
        if control["raise_"] is not None:
            raise control["raise_"]
        headers = control["headers"]
        if include is None:
            return dict(headers)
        wanted = {h.lower() for h in include}
        return {k: v for k, v in headers.items() if k.lower() in wanted}

    deps = types.ModuleType("fastmcp.server.dependencies")
    deps.get_http_headers = get_http_headers
    server = types.ModuleType("fastmcp.server")
    server.dependencies = deps
    root = types.ModuleType("fastmcp")
    root.server = server

    monkeypatch.setitem(sys.modules, "fastmcp", root)
    monkeypatch.setitem(sys.modules, "fastmcp.server", server)
    monkeypatch.setitem(sys.modules, "fastmcp.server.dependencies", deps)
    return control


@pytest.fixture
def no_fastmcp(monkeypatch):
    """Make importing fastmcp fail, as in an install without it."""
    for name in ("fastmcp", "fastmcp.server", "fastmcp.server.dependencies"):
        monkeypatch.setitem(sys.modules, name, None)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    monkeypatch.delenv(TOKEN_LOCATION_ENV, raising=False)
    monkeypatch.delenv(TOKEN_ENV, raising=False)


class TestRequestHeaders:
    def test_returns_the_requested_headers(self, fake_fastmcp):
        fake_fastmcp["headers"] = {"authorization": "Bearer t", "user-agent": "x"}
        assert adapter.request_headers() == {"authorization": "Bearer t"}

    def test_include_none_asks_for_everything(self, fake_fastmcp):
        fake_fastmcp["headers"] = {"authorization": "Bearer t", "user-agent": "x"}
        assert adapter.request_headers(None) == {"authorization": "Bearer t", "user-agent": "x"}

    def test_empty_outside_a_request_scope(self, fake_fastmcp):
        fake_fastmcp["raise_"] = RuntimeError("no active request")
        assert adapter.request_headers() == {}

    def test_empty_when_fastmcp_is_not_installed(self, no_fastmcp):
        assert adapter.request_headers() == {}

    def test_none_result_is_normalized(self, fake_fastmcp, monkeypatch):
        monkeypatch.setattr(
            sys.modules["fastmcp.server.dependencies"], "get_http_headers", lambda include=None: None
        )
        assert adapter.request_headers() == {}

    def test_availability_probe(self, fake_fastmcp, no_fastmcp):
        # no_fastmcp is applied last, so the probe must report False.
        assert adapter.fastmcp_available() is False

    def test_availability_probe_true(self, fake_fastmcp):
        assert adapter.fastmcp_available() is True


class TestRequestTokenProvider:
    def test_reads_the_bearer_token(self, fake_fastmcp, token):
        fake_fastmcp["headers"] = {"authorization": f"Bearer {token}"}
        assert adapter.RequestTokenProvider().get_token() == token

    def test_resolves_per_call_not_at_construction(self, fake_fastmcp, token):
        provider = adapter.RequestTokenProvider()
        assert provider.get_token() is None
        fake_fastmcp["headers"] = {"authorization": f"Bearer {token}"}
        assert provider.get_token() == token

    def test_source_label(self):
        assert adapter.RequestTokenProvider().source == "bearer"

    def test_custom_header_and_scheme(self, fake_fastmcp, token):
        fake_fastmcp["headers"] = {"x-fabric-token": f"Token {token}"}
        provider = adapter.RequestTokenProvider(header_name="x-fabric-token", scheme="token")
        assert provider.get_token() == token


class TestConvenienceHelpers:
    def test_current_token(self, fake_fastmcp, token):
        fake_fastmcp["headers"] = {"authorization": f"Bearer {token}"}
        assert adapter.current_token() == token

    def test_current_token_none_when_absent(self, fake_fastmcp):
        assert adapter.current_token() is None

    def test_current_claims(self, fake_fastmcp, token):
        fake_fastmcp["headers"] = {"authorization": f"Bearer {token}"}
        assert adapter.current_claims().email == "user@example.org"

    def test_current_claims_empty_when_absent(self, fake_fastmcp):
        assert not adapter.current_claims()

    def test_require_current_token(self, fake_fastmcp, token):
        fake_fastmcp["headers"] = {"authorization": f"Bearer {token}"}
        assert adapter.require_current_token() == token

    def test_require_current_token_raises(self, fake_fastmcp):
        with pytest.raises(MissingTokenError):
            adapter.require_current_token()


class TestServerMode:
    def test_uses_the_request_header(self, fake_fastmcp, token):
        fake_fastmcp["headers"] = {"authorization": f"Bearer {token}"}
        resolver = adapter.build_resolver(local_mode=False)
        ctx = resolver.resolve()
        assert ctx.token == token
        assert ctx.source == "bearer"

    def test_raises_without_a_header(self, fake_fastmcp):
        with pytest.raises(MissingTokenError):
            adapter.build_resolver(local_mode=False).resolve()

    def test_never_falls_back_to_a_local_token_file(self, fake_fastmcp, tmp_path, monkeypatch):
        # A server must not serve requests with the operator's own credential.
        p = tmp_path / "tok.json"
        p.write_text(json.dumps({"id_token": "operator-token"}))
        monkeypatch.setenv(TOKEN_LOCATION_ENV, str(p))
        with pytest.raises(MissingTokenError):
            adapter.build_resolver(local_mode=False).resolve()


class TestLocalMode:
    def test_reads_the_token_file(self, fake_fastmcp, tmp_path, monkeypatch):
        p = tmp_path / "tok.json"
        p.write_text(json.dumps({"id_token": "file-token"}))
        monkeypatch.setenv(TOKEN_LOCATION_ENV, str(p))
        ctx = adapter.build_resolver(local_mode=True).resolve()
        assert ctx.token == "file-token"
        assert ctx.source == "file"

    def test_accepts_an_explicit_token_location(self, fake_fastmcp, tmp_path):
        p = tmp_path / "tok.json"
        p.write_text(json.dumps({"id_token": "explicit"}))
        assert adapter.build_resolver(local_mode=True, token_location=p).resolve().token == "explicit"

    def test_falls_back_to_the_bare_env_var(self, fake_fastmcp, monkeypatch):
        monkeypatch.setenv(TOKEN_ENV, "env-token")
        ctx = adapter.build_resolver(local_mode=True).resolve()
        assert ctx.token == "env-token"
        assert ctx.source == "env"

    def test_a_bearer_header_takes_precedence(self, fake_fastmcp, tmp_path, monkeypatch, token):
        p = tmp_path / "tok.json"
        p.write_text(json.dumps({"id_token": "file-token"}))
        monkeypatch.setenv(TOKEN_LOCATION_ENV, str(p))
        fake_fastmcp["headers"] = {"authorization": f"Bearer {token}"}
        ctx = adapter.build_resolver(local_mode=True).resolve()
        assert ctx.token == token
        assert ctx.source == "bearer"

    def test_header_fallback_can_be_disabled(self, fake_fastmcp, tmp_path, monkeypatch, token):
        p = tmp_path / "tok.json"
        p.write_text(json.dumps({"id_token": "file-token"}))
        monkeypatch.setenv(TOKEN_LOCATION_ENV, str(p))
        fake_fastmcp["headers"] = {"authorization": f"Bearer {token}"}
        resolver = adapter.build_resolver(local_mode=True, allow_header_in_local_mode=False)
        assert resolver.resolve().token == "file-token"

    def test_misconfigured_local_mode_reports_a_missing_token(self, fake_fastmcp):
        with pytest.raises(MissingTokenError):
            adapter.build_resolver(local_mode=True).resolve()

    def test_works_without_fastmcp_installed(self, no_fastmcp, tmp_path, monkeypatch):
        p = tmp_path / "tok.json"
        p.write_text(json.dumps({"id_token": "file-token"}))
        monkeypatch.setenv(TOKEN_LOCATION_ENV, str(p))
        assert adapter.build_resolver(local_mode=True).resolve().token == "file-token"


class TestClientIp:
    def test_reads_the_proxy_headers(self, fake_fastmcp):
        fake_fastmcp["headers"] = {"x-real-ip": "1.1.1.1"}
        assert adapter.current_client_ip() == "1.1.1.1"

    def test_empty_string_when_no_header_identifies_one(self, fake_fastmcp):
        # No socket peer is available to a FastMCP tool, hence "" not "unknown".
        assert adapter.current_client_ip() == ""

    def test_default_is_configurable(self, fake_fastmcp):
        assert adapter.current_client_ip(default="unknown") == "unknown"

    def test_prefetched_headers_are_used_verbatim(self, fake_fastmcp):
        fake_fastmcp["headers"] = {"x-real-ip": "ignored"}
        assert adapter.current_client_ip({"x-real-ip": "2.2.2.2"}) == "2.2.2.2"

    def test_works_without_fastmcp(self, no_fastmcp):
        assert adapter.current_client_ip() == ""


class TestTraceContext:
    def test_collects_identity_request_id_and_ip(self, fake_fastmcp, token):
        fake_fastmcp["headers"] = {
            "authorization": f"Bearer {token}",
            "x-request-id": "rid-123",
            "x-real-ip": "1.1.1.1",
        }
        assert adapter.current_trace_context() == {
            "request_id": "rid-123",
            "user_sub": "http://cilogon.org/serverA/users/12345",
            "user_email": "user@example.org",
            "user_uuid": "user-uuid-1",
            "project_name": "Project One",
            "project_uuid": "project-uuid-1",
            "client_ip": "1.1.1.1",
        }

    def test_requests_all_tracing_headers(self, fake_fastmcp):
        adapter.current_trace_context()
        requested = set(fake_fastmcp["include_seen"][0])
        assert {"authorization", "x-request-id", "x-real-ip", "x-forwarded-for"} <= requested

    def test_empty_values_when_unauthenticated(self, fake_fastmcp):
        assert adapter.current_trace_context() == {
            "request_id": None,
            "user_sub": "",
            "user_email": "",
            "user_uuid": "",
            "project_name": "",
            "project_uuid": "",
            "client_ip": "",
        }

    def test_request_id_is_none_not_empty_so_callers_can_generate_one(self, fake_fastmcp):
        fake_fastmcp["headers"] = {"x-request-id": ""}
        assert adapter.current_trace_context()["request_id"] is None

    def test_header_names_are_case_insensitive(self, fake_fastmcp, token):
        fake_fastmcp["headers"] = {"Authorization": f"Bearer {token}", "X-Request-ID": "rid"}
        trace = adapter.current_trace_context()
        assert trace["request_id"] == "rid"
        assert trace["user_email"] == "user@example.org"

    def test_never_includes_the_token(self, fake_fastmcp, token):
        fake_fastmcp["headers"] = {"authorization": f"Bearer {token}"}
        assert token not in str(adapter.current_trace_context())

    def test_garbage_token_yields_empty_identity_without_raising(self, fake_fastmcp):
        fake_fastmcp["headers"] = {"authorization": "Bearer garbage"}
        assert adapter.current_trace_context()["user_sub"] == ""

    def test_outside_a_request_scope(self, fake_fastmcp):
        fake_fastmcp["raise_"] = RuntimeError("no request")
        assert adapter.current_trace_context()["request_id"] is None

    def test_works_without_fastmcp(self, no_fastmcp):
        assert adapter.current_trace_context()["user_email"] == ""

    def test_prefetched_headers_avoid_a_second_fetch(self, fake_fastmcp, token):
        adapter.current_trace_context({"authorization": f"Bearer {token}"})
        assert fake_fastmcp["include_seen"] == []


class TestResolverPolicyPassthrough:
    def test_expiry_enforcement_is_forwarded(self, fake_fastmcp, expired_token):
        fake_fastmcp["headers"] = {"authorization": f"Bearer {expired_token}"}
        resolver = adapter.build_resolver(local_mode=False, enforce_expiry=True)
        assert resolver.enforce_expiry is True
        assert resolver.try_resolve() is None

    def test_verifier_is_forwarded(self, fake_fastmcp, token):
        from fabric_mcp_common.auth.claims import TokenClaims

        class Verifier:
            def verify(self, tok):
                return TokenClaims({"sub": "v"}, verified=True)

        fake_fastmcp["headers"] = {"authorization": f"Bearer {token}"}
        resolver = adapter.build_resolver(local_mode=False, verifier=Verifier())
        assert resolver.resolve().verified is True
