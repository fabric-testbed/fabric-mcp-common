"""Shared fixtures: minimal unsigned JWTs for decode-path tests."""
from __future__ import annotations

import base64
import json
import time
from typing import Any, Dict, Optional

import pytest


def b64url(data: Dict[str, Any]) -> str:
    """Encode a dict as an unpadded base64url JWT segment."""
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")


def make_token(
    payload: Optional[Dict[str, Any]] = None,
    *,
    header: Optional[Dict[str, Any]] = None,
    signature: str = "not-a-real-signature",
) -> str:
    """Build a syntactically valid, cryptographically meaningless JWT."""
    header = header or {"alg": "RS256", "typ": "JWT", "kid": "test-key"}
    return f"{b64url(header)}.{b64url(payload or {})}.{signature}"


@pytest.fixture
def payload() -> Dict[str, Any]:
    return {
        "sub": "http://cilogon.org/serverA/users/12345",
        "email": "user@example.org",
        "name": "Test User",
        "uuid": "user-uuid-1",
        "iss": "https://cilogon.org",
        "aud": "cilogon:/client_id/abc123",
        "iat": int(time.time()) - 60,
        "exp": int(time.time()) + 3600,
        "projects": [
            {"name": "Project One", "uuid": "project-uuid-1", "tags": ["Net.FABNetv4"]},
            {"name": "Project Two", "uuid": "project-uuid-2"},
        ],
    }


@pytest.fixture
def token(payload) -> str:
    return make_token(payload)


@pytest.fixture
def expired_token(payload) -> str:
    payload = dict(payload, exp=int(time.time()) - 30)
    return make_token(payload)


class FakeClient:
    def __init__(self, host: str = "10.0.0.9") -> None:
        self.host = host


class FakeURL:
    def __init__(self, path: str = "/mcp") -> None:
        self.path = path


class FakeState:
    pass


class FakeRequest:
    """Duck-typed stand-in for a Starlette request."""

    def __init__(self, headers=None, path="/mcp", client_host="10.0.0.9"):
        self.headers = dict(headers or {})
        self.url = FakeURL(path)
        self.client = FakeClient(client_host) if client_host else None
        self.state = FakeState()


@pytest.fixture
def request_factory():
    return FakeRequest


@pytest.fixture
def count_opens(monkeypatch):
    """Context manager recording the paths passed to ``open`` while active."""
    import builtins
    import contextlib

    real_open = builtins.open

    @contextlib.contextmanager
    def _counter():
        calls = []

        def counting_open(file, *args, **kwargs):
            calls.append(file)
            return real_open(file, *args, **kwargs)

        monkeypatch.setattr(builtins, "open", counting_open)
        try:
            yield calls
        finally:
            monkeypatch.setattr(builtins, "open", real_open)

    return _counter
