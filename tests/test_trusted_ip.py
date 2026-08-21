"""Security-grade client address and rate-limit key.

The old rate_limit_key took the claim from an unverified decode and fell back to
the left-most X-Forwarded-For entry. Both are caller-controlled, so a caller
could rotate either for a fresh bucket per request and bypass the limit outright.
These tests state the attacks and assert they no longer work.
"""
from __future__ import annotations

import base64
import json

import pytest

from fabric_mcp_common.auth import TokenClaims
from fabric_mcp_common.integrations.starlette import (
    CLAIMS_STATE_ATTR,
    peer_ip,
    rate_limit_key,
    trusted_client_ip,
)
from fabric_mcp_common.net import invalid_networks, peer_in_networks

PROXY = "172.31.240.10"
PROXY_NET = "172.31.240.10/32"
DIRECT = "198.51.100.4"


def forge_jwt(**claims) -> str:
    """A JWT with arbitrary claims and a junk signature — no signing key needed."""
    def b64(data):
        return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()

    return f"{b64({'alg': 'RS256'})}.{b64(claims)}.not-a-real-signature"


class Request:
    """Duck-typed request: headers, client peer, and a state object."""

    class _Client:
        def __init__(self, host):
            self.host = host

    class _State:
        pass

    def __init__(self, *, peer=DIRECT, headers=None, token=None):
        self.headers = dict(headers or {})
        if token is not None:
            self.headers["authorization"] = f"Bearer {token}"
        self.client = self._Client(peer) if peer else None
        self.state = self._State()


class TestPeerInNetworks:
    def test_matches_an_exact_host(self):
        assert peer_in_networks(PROXY, [PROXY_NET])

    def test_rejects_a_neighbour(self):
        assert not peer_in_networks("172.31.240.11", [PROXY_NET])

    def test_matches_within_a_range(self):
        assert peer_in_networks("10.1.2.3", ["10.0.0.0/8"])

    def test_supports_ipv6(self):
        assert peer_in_networks("::1", ["::1/128"])
        assert not peer_in_networks("::2", ["::1/128"])

    @pytest.mark.parametrize("host", [None, "", "not-an-ip", "unix:/tmp/sock"])
    def test_unusable_peers_are_never_trusted(self, host):
        assert not peer_in_networks(host, ["0.0.0.0/0"])

    def test_empty_network_list_trusts_nothing(self):
        assert not peer_in_networks(PROXY, [])

    def test_malformed_entries_are_skipped_not_raised(self):
        assert peer_in_networks(PROXY, ["not-a-cidr", PROXY_NET])
        assert not peer_in_networks(PROXY, ["not-a-cidr"])

    def test_invalid_networks_reports_them_for_startup_logging(self):
        assert invalid_networks(["10.0.0.0/8", "nope", "also/bad"]) == ["nope", "also/bad"]


class TestTrustedClientIp:
    def test_defaults_to_trusting_no_proxy(self):
        request = Request(peer=PROXY, headers={"x-real-ip": "203.0.113.9"})
        assert trusted_client_ip(request) == PROXY

    def test_uses_the_header_from_a_trusted_peer(self):
        request = Request(peer=PROXY, headers={"x-real-ip": "203.0.113.9"})
        assert trusted_client_ip(request, trusted_proxies=[PROXY_NET]) == "203.0.113.9"

    def test_ignores_the_header_from_an_untrusted_peer(self):
        request = Request(peer=DIRECT, headers={"x-real-ip": "10.9.9.9"})
        assert trusted_client_ip(request, trusted_proxies=[PROXY_NET]) == DIRECT

    def test_header_lookup_is_case_insensitive(self):
        request = Request(peer=PROXY, headers={"X-Real-IP": "203.0.113.9"})
        assert trusted_client_ip(request, trusted_proxies=[PROXY_NET]) == "203.0.113.9"

    def test_falls_back_to_the_peer_when_the_header_is_absent(self):
        request = Request(peer=PROXY)
        assert trusted_client_ip(request, trusted_proxies=[PROXY_NET]) == PROXY

    def test_clientless_request_uses_the_default(self):
        assert trusted_client_ip(Request(peer=None), default="unknown") == "unknown"

    def test_x_forwarded_for_is_not_consulted_by_default(self):
        # Proxies append to XFF, so its left-most entry stays caller-controlled.
        request = Request(peer=PROXY, headers={"x-forwarded-for": "1.2.3.4, 203.0.113.9"})
        assert trusted_client_ip(request, trusted_proxies=[PROXY_NET]) == PROXY

    def test_spoofing_from_an_untrusted_peer_yields_one_key(self):
        keys = {
            trusted_client_ip(
                Request(peer=DIRECT, headers={"x-real-ip": forged}),
                trusted_proxies=[PROXY_NET],
            )
            for forged in ("1.1.1.1", "2.2.2.2", "3.3.3.3")
        }
        assert keys == {DIRECT}


class TestPeerIp:
    def test_returns_the_socket_peer(self):
        assert peer_ip(Request(peer=DIRECT)) == DIRECT

    def test_returns_the_default_without_a_client(self):
        assert peer_ip(Request(peer=None), default="none") == "none"


class TestRateLimitKeyRequiresVerifiedClaims:
    def test_an_unverified_subject_is_ignored_by_default(self):
        request = Request(peer=DIRECT, token=forge_jwt(sub="attacker"))
        assert rate_limit_key(request) == DIRECT

    def test_rotating_forged_subjects_cannot_mint_buckets(self):
        keys = {
            rate_limit_key(Request(peer=DIRECT, token=forge_jwt(sub=f"a-{i}")))
            for i in range(6)
        }
        assert keys == {DIRECT}

    def test_a_verified_subject_is_used(self):
        request = Request(peer=DIRECT)
        setattr(
            request.state,
            CLAIMS_STATE_ATTR,
            TokenClaims({"sub": "real-user"}, verified=True),
        )
        assert rate_limit_key(request) == "real-user"

    def test_require_verified_can_be_turned_off_deliberately(self):
        # Documented escape hatch for deployments where something upstream has
        # already authenticated the token.
        request = Request(peer=DIRECT, token=forge_jwt(sub="upstream-checked"))
        assert rate_limit_key(request, require_verified=False) == "upstream-checked"

    def test_verified_claims_without_the_claim_fall_through(self):
        request = Request(peer=DIRECT)
        setattr(request.state, CLAIMS_STATE_ATTR, TokenClaims({}, verified=True))
        assert rate_limit_key(request) == DIRECT


class TestRateLimitKeyAddressFallback:
    def test_behind_a_trusted_proxy_callers_get_separate_buckets(self):
        keys = {
            rate_limit_key(
                Request(peer=PROXY, headers={"x-real-ip": f"203.0.113.{i}"}),
                trusted_proxies=[PROXY_NET],
            )
            for i in range(1, 6)
        }
        assert len(keys) == 5

    def test_without_configured_proxies_everyone_shares_the_peer(self):
        # Safe, but a service-wide cap behind a proxy — callers must configure.
        keys = {
            rate_limit_key(Request(peer=PROXY, headers={"x-real-ip": f"203.0.113.{i}"}))
            for i in range(1, 6)
        }
        assert keys == {PROXY}

    def test_forged_xff_cannot_influence_the_key(self):
        keys = {
            rate_limit_key(
                Request(
                    peer=PROXY,
                    headers={"x-forwarded-for": f"{f}, 203.0.113.9", "x-real-ip": "203.0.113.9"},
                ),
                trusted_proxies=[PROXY_NET],
            )
            for f in ("1.1.1.1", "2.2.2.2", "3.3.3.3")
        }
        assert keys == {"203.0.113.9"}

    def test_default_is_used_when_nothing_identifies_the_caller(self):
        assert rate_limit_key(Request(peer=None), default="fallback") == "fallback"
