"""The FastMCP adapter, against the *real* framework.

``test_integrations_fastmcp.py`` stubs fastmcp out — deliberately, so the unit
tests are fast and the core stays dependency-free. The cost is that nothing there
would notice fastmcp renaming, moving or re-signaturing the one function the
adapter depends on: ``fastmcp.server.dependencies.get_http_headers``.

That is the same shape as the break that took a downstream deploy down — an
upstream release, no change here, and a consumer discovering it in production.
This module closes it by exercising the adapter through fastmcp's own ASGI app.

Skipped unless fastmcp is installed, so the default ``[test]`` run is unaffected —
**except** when ``FMC_REQUIRE_FASTMCP`` is set, which CI does in the job that
installs the extra on purpose. There, a failed import is the break this file
exists to catch, and skipping would report green: the job runs the whole suite,
so a skipped file leaves ~498 other tests passing and an exit code of 0.

That is not hypothetical. ``pytest.importorskip`` alone made this file silently
inert whenever the installed fastmcp was broken — the exact condition it is
supposed to detect.
"""
from __future__ import annotations

import importlib
import inspect
import os

import pytest

#: Set by CI wherever the [fastmcp] extra is installed deliberately. Turns "I
#: could not import it" from a skip into a failure.
REQUIRE_FASTMCP = os.environ.get("FMC_REQUIRE_FASTMCP", "") not in (
    "",
    "0",
    "false",
    "False",
)


def _require_or_skip(module: str) -> None:
    try:
        importlib.import_module(module)
    except Exception as exc:  # noqa: BLE001 - any import failure counts
        if REQUIRE_FASTMCP:
            raise RuntimeError(
                f"FMC_REQUIRE_FASTMCP is set but {module!r} failed to import: "
                f"{exc!r}. The extra is installed in this job, so this is a real "
                "break — not a reason to skip these tests."
            ) from exc
        pytest.skip(
            f"requires the [fastmcp] extra ({module} unavailable)",
            allow_module_level=True,
        )


_require_or_skip("fastmcp")
_require_or_skip("starlette")

from fabric_mcp_common.integrations.fastmcp import (  # noqa: E402
    current_token,
    fastmcp_available,
    request_headers,
)

#: The adapter's entire dependency on fastmcp. Kept explicit so a change upstream
#: fails here with a pointed message rather than somewhere in a consumer.
DEPENDENCY = "fastmcp.server.dependencies.get_http_headers"


class TestTheDependencyStillExists:
    def test_adapter_reports_fastmcp_available(self):
        assert fastmcp_available() is True

    def test_get_http_headers_is_importable(self):
        from fastmcp.server.dependencies import get_http_headers  # noqa: F401

    def test_it_still_accepts_the_include_argument(self):
        # `include` is an *un-exclude* list, not a filter: fastmcp strips a
        # blocklist by default and `include` keeps the named ones anyway.
        # authorization is on that blocklist, so this argument is what makes
        # current_token() able to see a token at all. Losing it would not raise
        # at import — every authenticated call would silently look anonymous.
        from fastmcp.server.dependencies import get_http_headers

        params = inspect.signature(get_http_headers).parameters
        assert "include" in params, f"{DEPENDENCY} no longer accepts include="


class TestOutsideARequestScope:
    """Tool calls happen off the request path too — background tasks, stdio."""

    def test_current_token_returns_none_rather_than_raising(self):
        assert current_token() is None

    def test_request_headers_returns_empty_rather_than_raising(self):
        assert request_headers() == {}


class TestThroughFastmcpsOwnAsgiApp:
    """End to end: a real Authorization header on a real fastmcp app.

    This is the part a signature check cannot give. It proves the header actually
    reaches the adapter, through whatever context mechanism fastmcp currently
    uses — so a change in *how* the context is propagated fails here too.
    """

    @staticmethod
    def _probe_client():
        from fastmcp import FastMCP
        from starlette.responses import PlainTextResponse
        from starlette.testclient import TestClient

        mcp = FastMCP(name="contract-probe")

        @mcp.custom_route("/probe", methods=["GET"])
        async def probe(_request):  # noqa: ANN001
            return PlainTextResponse(current_token() or "NONE")

        @mcp.custom_route("/default-include", methods=["GET"])
        async def default_include(_request):  # noqa: ANN001
            # The adapter's default: include=("authorization",).
            return PlainTextResponse(
                "yes" if "authorization" in request_headers() else "no"
            )

        @mcp.custom_route("/no-include", methods=["GET"])
        async def no_include(_request):  # noqa: ANN001
            # include=None accepts fastmcp's defaults, which strip authorization.
            return PlainTextResponse(
                "yes" if "authorization" in request_headers(include=None) else "no"
            )

        return TestClient(mcp.http_app())

    def test_a_bearer_token_reaches_the_adapter(self):
        with self._probe_client() as client:
            response = client.get(
                "/probe", headers={"authorization": "Bearer real-token-123"}
            )
            assert response.text == "real-token-123"

    def test_no_header_yields_no_token(self):
        with self._probe_client() as client:
            assert client.get("/probe").text == "NONE"

    def test_a_non_bearer_scheme_is_not_accepted(self):
        with self._probe_client() as client:
            response = client.get("/probe", headers={"authorization": "Basic abc123"})
            assert response.text == "NONE"

    def test_the_default_include_keeps_the_authorization_header(self):
        # The load-bearing assertion in this file. fastmcp strips authorization
        # unless asked to keep it, so if upstream stopped honouring `include`,
        # every authenticated call would silently look anonymous rather than
        # failing loudly.
        with self._probe_client() as client:
            response = client.get(
                "/default-include", headers={"authorization": "Bearer t"}
            )
            assert response.text == "yes", (
                "authorization was stripped despite the adapter opting in — "
                "current_token() would return None for every caller"
            )

    def test_include_none_accepts_fastmcps_defaults_and_drops_it(self):
        # Pins the surprising half of the semantics: include= is an un-exclude
        # list, so None means "fastmcp's defaults", which exclude authorization.
        # Documented on request_headers(); asserted here so it stays true.
        with self._probe_client() as client:
            response = client.get("/no-include", headers={"authorization": "Bearer t"})
            assert response.text == "no"
