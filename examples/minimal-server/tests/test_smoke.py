"""Smoke tests for the skeleton.

Deliberately thin — they exist to prove the wiring holds, and to show the two
checks worth copying into a real server: the security defaults, and that every
module imports.
"""
from __future__ import annotations

import importlib

import pytest

MODULES = (
    "my_mcp",
    "my_mcp.config",
    "my_mcp.observability",
    "my_mcp.auth",
    "my_mcp.rate_limit",
    "my_mcp.tools.example",
    "my_mcp.__main__",
)


@pytest.mark.parametrize("name", MODULES)
def test_module_imports(name):
    assert importlib.import_module(name) is not None


class TestSecurityDefaults:
    """These defaults are the point of the skeleton. Guard them."""

    def test_no_proxy_is_trusted_by_default(self, monkeypatch):
        from my_mcp.config import ServerConfig

        monkeypatch.delenv("RATE_LIMIT_TRUSTED_PROXIES", raising=False)
        assert ServerConfig.from_env().rate_limit_trusted_proxies == ()

    def test_a_forged_subject_cannot_decide_the_key(self):
        # An unverified JWT claim is attacker input: a payload can be built by
        # hand with no signing key. Many forged subjects, one bucket.
        import base64
        import json

        from starlette.requests import Request

        from my_mcp.rate_limit import rate_limit_identity

        def forge(sub):
            b64 = lambda d: base64.urlsafe_b64encode(  # noqa: E731
                json.dumps(d).encode()
            ).rstrip(b"=").decode()
            return f"{b64({'alg': 'RS256'})}.{b64({'sub': sub})}.not-a-signature"

        def req(sub):
            return Request(
                {
                    "type": "http",
                    "http_version": "1.1",
                    "method": "POST",
                    "scheme": "http",
                    "path": "/mcp",
                    "raw_path": b"/mcp",
                    "query_string": b"",
                    "root_path": "",
                    "headers": [(b"authorization", f"Bearer {forge(sub)}".encode())],
                    "client": ("198.51.100.4", 1),
                    "server": ("t", 80),
                }
            )

        keys = {rate_limit_identity(req(f"attacker-{i}"))[0] for i in range(5)}
        assert keys == {"198.51.100.4"}

    def test_key_type_matches_the_key(self):
        # The label must describe how the request was really bucketed, or a
        # dashboard overstates what the limiter does.
        from starlette.requests import Request

        from my_mcp.rate_limit import rate_limit_identity

        request = Request(
            {
                "type": "http",
                "http_version": "1.1",
                "method": "POST",
                "scheme": "http",
                "path": "/mcp",
                "raw_path": b"/mcp",
                "query_string": b"",
                "root_path": "",
                "headers": [],
                "client": ("198.51.100.4", 1),
                "server": ("t", 80),
            }
        )
        key, kind = rate_limit_identity(request)
        assert (key, kind) == ("198.51.100.4", "ip")
