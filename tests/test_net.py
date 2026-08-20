"""Tests for proxy-header client IP resolution."""
from __future__ import annotations

import pytest

from fabric_mcp_common.net import DEFAULT_FORWARDED_HEADERS, client_ip_from_headers


class TestClientIpFromHeaders:
    def test_prefers_x_real_ip(self):
        headers = {"x-real-ip": "1.1.1.1", "x-forwarded-for": "2.2.2.2"}
        assert client_ip_from_headers(headers) == "1.1.1.1"

    def test_falls_back_to_x_forwarded_for(self):
        assert client_ip_from_headers({"x-forwarded-for": "2.2.2.2"}) == "2.2.2.2"

    def test_takes_the_leftmost_hop(self):
        assert client_ip_from_headers({"x-forwarded-for": "3.3.3.3, 4.4.4.4"}) == "3.3.3.3"

    def test_header_names_are_case_insensitive(self):
        assert client_ip_from_headers({"X-Real-IP": "1.1.1.1"}) == "1.1.1.1"

    @pytest.mark.parametrize(
        "headers",
        [None, {}, {"x-real-ip": ""}, {"x-real-ip": "  "}, {"x-forwarded-for": " , "}],
    )
    def test_returns_none_when_nothing_identifies_an_ip(self, headers):
        assert client_ip_from_headers(headers) is None

    def test_skips_a_blank_higher_precedence_header(self):
        headers = {"x-real-ip": "   ", "x-forwarded-for": "2.2.2.2"}
        assert client_ip_from_headers(headers) == "2.2.2.2"

    def test_header_precedence_is_configurable(self):
        headers = {"cf-connecting-ip": "9.9.9.9", "x-real-ip": "1.1.1.1"}
        assert client_ip_from_headers(headers, forwarded_headers=("cf-connecting-ip",)) == "9.9.9.9"

    def test_non_string_values_are_coerced(self):
        assert client_ip_from_headers({"x-real-ip": 12345}) == "12345"

    def test_non_string_keys_are_ignored(self):
        assert client_ip_from_headers({1: "x", "x-real-ip": "1.1.1.1"}) == "1.1.1.1"

    def test_non_mapping_input_does_not_raise(self):
        assert client_ip_from_headers(["not", "a", "mapping"]) is None

    def test_default_order_is_documented(self):
        assert tuple(DEFAULT_FORWARDED_HEADERS) == ("x-real-ip", "x-forwarded-for")
