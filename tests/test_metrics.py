"""Tests for the metric contract, cardinality controls, and middleware."""
from __future__ import annotations

import json
import re

import pytest

from fabric_mcp_common import metrics as m
from fabric_mcp_common.metrics import definitions as d


@pytest.fixture(autouse=True)
def reset_policy():
    """Cardinality policy is process-global; restore it between tests."""
    before = d.client_ip_labels_enabled()
    yield
    d.configure(client_ip_labels=before)


def sample(metric, **labels):
    """Current value of a labelled counter/gauge sample."""
    for mf in metric.collect():
        for s in mf.samples:
            if all(s.labels.get(k) == v for k, v in labels.items()) and not s.name.endswith(
                ("_created", "_bucket", "_sum")
            ):
                return s.value
    return None


class TestContract:
    def test_all_eleven_metrics_are_present(self):
        assert len(m.ALL_METRICS) == 11

    def test_every_dashboard_metric_exists_in_the_contract(self):
        # The bundled dashboard must work unedited against any adopting server.
        text = m.dashboard_path().read_text()
        referenced = set(re.findall(r"mcp_[a-z_]+", text))
        # Histogram queries use the _bucket/_sum/_count suffixes.
        stripped = {
            re.sub(r"_(bucket|sum|count)$", "", name) for name in referenced
        }
        unknown = stripped - set(m.METRIC_NAMES)
        assert unknown == set(), f"dashboard queries metrics not in the contract: {unknown}"

    def test_declared_names_are_actually_exposed(self):
        from prometheus_client import generate_latest

        exposed = generate_latest(m.DEFAULT_REGISTRY).decode()
        missing = [n for n in m.METRIC_NAMES if n not in exposed]
        assert missing == [], f"declared but not exposed: {missing}"

    def test_dashboard_ships_as_package_data(self):
        path = m.dashboard_path()
        assert path.is_file()
        assert json.loads(path.read_text())["panels"]

    def test_dashboard_is_not_server_specific(self):
        text = m.dashboard_path().read_text().lower()
        assert "fabric" not in text

    def test_buckets_are_ascending(self):
        assert list(m.BUCKETS) == sorted(m.BUCKETS)


class TestCardinalityPolicy:
    def test_client_ip_labels_are_off_by_default(self):
        # A fresh process must not mint one series per source address.
        assert d._client_ip_enabled is False

    def test_disabled_policy_returns_a_constant(self):
        d.configure(client_ip_labels=False)
        assert m.ip_label("203.0.113.9") == m.IP_DISABLED
        assert m.ip_label(None) == m.IP_DISABLED

    def test_enabled_policy_records_the_address(self):
        d.configure(client_ip_labels=True)
        assert m.ip_label("203.0.113.9") == "203.0.113.9"

    def test_enabled_policy_labels_unknown_addresses(self):
        d.configure(client_ip_labels=True)
        assert m.ip_label(None) == "unknown"
        assert m.ip_label("") == "unknown"

    def test_policy_is_reportable(self):
        d.configure(client_ip_labels=True)
        assert m.client_ip_labels_enabled() is True
        d.configure(client_ip_labels=False)
        assert m.client_ip_labels_enabled() is False


class TestPathNormalization:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("/mcp", "/mcp"),
            ("/metrics", "/metrics"),
            ("/", "/"),
            ("/slices/7", "/slices/{id}"),
            ("/slices/2f1c9e4a-1b2c-3d4e-5f60-708192a3b4c5", "/slices/{id}"),
            ("/slices/2f1c9e4a-1b2c-3d4e-5f60-708192a3b4c5/nodes/12", "/slices/{id}/nodes/{id}"),
            ("/blob/deadbeefdeadbeef99", "/blob/{id}"),
        ],
    )
    def test_id_like_segments_are_collapsed(self, raw, expected):
        assert m.normalize_path(raw) == expected

    def test_static_mcp_routes_are_unchanged(self):
        # The paths FABRIC MCP actually serves must keep their existing labels.
        for path in ("/mcp", "/mcp/", "/metrics", "/health"):
            assert m.normalize_path(path) == path

    def test_empty_path_becomes_root(self):
        assert m.normalize_path("") == "/"

    def test_pathologically_deep_paths_are_truncated(self):
        assert m.normalize_path("/" + "/".join("abcdefghijklmnop")).endswith("...")


class TestRecordToolCall:
    def test_records_count_and_duration(self):
        before = sample(m.mcp_tool_calls_total, tool="t1", status="ok") or 0
        m.record_tool_call(tool="t1", duration_seconds=0.5, user_uuid="u", user_email="e")
        after = sample(m.mcp_tool_calls_total, tool="t1", status="ok")
        assert after == before + 1

    def test_error_status_is_separate(self):
        m.record_tool_call(tool="t2", duration_seconds=0.1, status="error")
        assert sample(m.mcp_tool_calls_total, tool="t2", status="error") == 1
        assert sample(m.mcp_tool_calls_total, tool="t2", status="ok") is None

    def test_never_raises_on_bad_input(self):
        # Instrumentation must not turn a served call into a failed one.
        m.record_tool_call(tool="t3", duration_seconds="not-a-number")  # type: ignore[arg-type]


class TestMiddleware:
    @pytest.fixture
    def client(self):
        from starlette.applications import Starlette
        from starlette.responses import JSONResponse
        from starlette.routing import Route
        from starlette.testclient import TestClient

        async def ok(request):
            return JSONResponse({"ok": True})

        async def boom(request):
            raise RuntimeError("boom")

        app = Starlette(
            routes=[
                Route("/mcp", ok),
                Route("/mcp/{slice_id}", ok),
                Route("/metrics", ok),
                Route("/health", ok),
                Route("/boom", boom),
            ]
        )
        app.add_middleware(m.SecurityMetricsMiddleware)
        app.add_middleware(m.MetricsMiddleware)
        return TestClient(app, raise_server_exceptions=False)

    def test_counts_requests(self, client):
        before = sample(m.mcp_http_requests_total, method="GET", path="/mcp", status="200") or 0
        client.get("/mcp")
        after = sample(m.mcp_http_requests_total, method="GET", path="/mcp", status="200")
        assert after == before + 1

    def test_metrics_endpoint_is_not_instrumented(self, client):
        before = sample(m.mcp_http_requests_total, method="GET", path="/metrics", status="200")
        client.get("/metrics")
        after = sample(m.mcp_http_requests_total, method="GET", path="/metrics", status="200")
        assert before is None and after is None

    def test_in_progress_gauge_returns_to_zero(self, client):
        client.get("/mcp")
        assert sample(m.mcp_http_requests_in_progress, method="GET") == 0

    def test_failures_are_recorded_as_500_and_gauge_still_decremented(self, client):
        client.get("/boom")
        assert sample(m.mcp_http_requests_total, method="GET", path="/boom", status="500") == 1
        assert sample(m.mcp_http_requests_in_progress, method="GET") == 0

    def test_id_bearing_paths_are_collapsed_into_one_series(self, client):
        client.get("/mcp/2f1c9e4a-1b2c-3d4e-5f60-708192a3b4c5")
        client.get("/mcp/9a8b7c6d-1b2c-3d4e-5f60-708192a3b4c5")
        assert sample(m.mcp_http_requests_total, method="GET", path="/mcp/{id}", status="200") == 2

    def test_missing_token_on_protected_path_is_a_failure(self, client):
        d.configure(client_ip_labels=False)
        before = sample(
            m.mcp_auth_failures_total, reason="missing_token", client_ip=m.IP_DISABLED
        ) or 0
        client.get("/mcp")
        after = sample(m.mcp_auth_failures_total, reason="missing_token", client_ip=m.IP_DISABLED)
        assert after == before + 1

    def test_open_path_without_credentials_is_not_a_failure(self, client):
        before = sample(
            m.mcp_auth_failures_total, reason="missing_token", client_ip=m.IP_DISABLED
        ) or 0
        client.get("/health")
        after = sample(
            m.mcp_auth_failures_total, reason="missing_token", client_ip=m.IP_DISABLED
        ) or 0
        assert after == before

    def test_malformed_header_is_classified(self, client):
        before = sample(
            m.mcp_auth_failures_total, reason="malformed_header", client_ip=m.IP_DISABLED
        ) or 0
        client.get("/mcp", headers={"Authorization": "Basic zzz"})
        after = sample(
            m.mcp_auth_failures_total, reason="malformed_header", client_ip=m.IP_DISABLED
        )
        assert after == before + 1

    def test_valid_token_records_a_success(self, client, token):
        before = sample(
            m.mcp_auth_success_total,
            user_uuid="user-uuid-1",
            user_email="user@example.org",
            client_ip=m.IP_DISABLED,
        ) or 0
        client.get("/mcp", headers={"Authorization": f"Bearer {token}"})
        after = sample(
            m.mcp_auth_success_total,
            user_uuid="user-uuid-1",
            user_email="user@example.org",
            client_ip=m.IP_DISABLED,
        )
        assert after == before + 1

    def test_per_user_counters_are_populated(self, client, token):
        before = sample(
            m.mcp_requests_by_user_total, user_uuid="user-uuid-1", user_email="user@example.org"
        ) or 0
        client.get("/mcp", headers={"Authorization": f"Bearer {token}"})
        after = sample(
            m.mcp_requests_by_user_total, user_uuid="user-uuid-1", user_email="user@example.org"
        )
        assert after == before + 1

    def test_ip_labels_are_recorded_when_enabled(self, client):
        d.configure(client_ip_labels=True)
        client.get("/mcp", headers={"X-Real-IP": "203.0.113.77"})
        assert sample(m.mcp_requests_by_ip_total, client_ip="203.0.113.77") == 1

    def test_one_decode_is_shared_across_the_stack(self, client, token):
        # Both middlewares read claims; the memoised request.state must be used.
        from fabric_mcp_common.integrations import starlette as st

        calls = []
        original = st.TokenClaims.from_token

        def counting(tok, **kw):
            calls.append(tok)
            return original(tok, **kw)

        st.TokenClaims.from_token = staticmethod(counting)
        try:
            client.get("/mcp", headers={"Authorization": f"Bearer {token}"})
        finally:
            st.TokenClaims.from_token = original
        assert len(calls) == 1
