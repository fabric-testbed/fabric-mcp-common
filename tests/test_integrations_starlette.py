"""Tests for the ASGI/Starlette adapter."""
from __future__ import annotations

import time

import pytest

from conftest import make_token
from fabric_mcp_common.auth.claims import TokenClaims
from fabric_mcp_common.integrations.starlette import (
    CLAIMS_STATE_ATTR,
    REASON_EXPIRED_TOKEN,
    REASON_INVALID_JWT,
    REASON_MALFORMED_HEADER,
    REASON_MISSING_TOKEN,
    UNKNOWN_IP,
    auth_failure_reason,
    client_ip,
    identity,
    identity_fields,
    rate_limit_key,
    request_claims,
    request_token,
)


@pytest.fixture
def bearer(token):
    return {"authorization": f"Bearer {token}"}


class TestClientIp:
    def test_prefers_x_real_ip(self, request_factory):
        req = request_factory({"x-real-ip": "1.1.1.1", "x-forwarded-for": "2.2.2.2"})
        assert client_ip(req) == "1.1.1.1"

    def test_falls_back_to_x_forwarded_for(self, request_factory):
        assert client_ip(request_factory({"x-forwarded-for": "2.2.2.2"})) == "2.2.2.2"

    def test_takes_the_leftmost_forwarded_hop(self, request_factory):
        req = request_factory({"x-forwarded-for": "3.3.3.3, 4.4.4.4, 5.5.5.5"})
        assert client_ip(req) == "3.3.3.3"

    def test_ignores_blank_forwarded_values(self, request_factory):
        req = request_factory({"x-real-ip": "  ", "x-forwarded-for": " , 4.4.4.4"})
        assert client_ip(req) == "10.0.0.9"

    def test_falls_back_to_the_socket_peer(self, request_factory):
        assert client_ip(request_factory({})) == "10.0.0.9"

    def test_unknown_when_no_source_available(self, request_factory):
        assert client_ip(request_factory({}, client_host=None)) == UNKNOWN_IP

    def test_header_names_are_case_insensitive(self, request_factory):
        assert client_ip(request_factory({"X-Real-IP": "1.1.1.1"})) == "1.1.1.1"

    def test_forwarded_headers_are_configurable(self, request_factory):
        req = request_factory({"cf-connecting-ip": "9.9.9.9", "x-real-ip": "1.1.1.1"})
        assert client_ip(req, forwarded_headers=("cf-connecting-ip",)) == "9.9.9.9"


class TestRequestTokenAndClaims:
    def test_extracts_the_token(self, request_factory, bearer, token):
        assert request_token(request_factory(bearer)) == token

    def test_none_without_a_header(self, request_factory):
        assert request_token(request_factory({})) is None

    def test_claims_are_decoded(self, request_factory, bearer):
        assert request_claims(request_factory(bearer)).email == "user@example.org"

    def test_claims_are_empty_when_unauthenticated(self, request_factory):
        assert not request_claims(request_factory({}))

    def test_claims_are_memoized_on_request_state(self, request_factory, bearer):
        req = request_factory(bearer)
        first = request_claims(req)
        assert getattr(req.state, CLAIMS_STATE_ATTR) is first
        assert request_claims(req) is first

    def test_cache_can_be_bypassed(self, request_factory, bearer):
        req = request_factory(bearer)
        first = request_claims(req)
        assert request_claims(req, cache=False) is not first

    def test_stale_cache_is_used_over_headers(self, request_factory, bearer):
        # Documents the memoization contract: state wins once populated.
        req = request_factory(bearer)
        setattr(req.state, CLAIMS_STATE_ATTR, TokenClaims({"email": "cached@example.org"}))
        assert request_claims(req).email == "cached@example.org"

    def test_requests_without_state_still_work(self, bearer):
        class Stateless:
            headers = bearer

        assert request_claims(Stateless()).email == "user@example.org"


class TestIdentity:
    def test_identity_prefers_email(self, request_factory, bearer):
        assert identity(request_factory(bearer)) == "user@example.org"

    def test_anonymous_without_a_token(self, request_factory):
        assert identity(request_factory({})) == "anonymous"

    def test_identity_fields_shape(self, request_factory, bearer):
        fields = identity_fields(request_factory(bearer))
        assert fields == {
            "user_sub": "http://cilogon.org/serverA/users/12345",
            "user_email": "user@example.org",
            "user_uuid": "user-uuid-1",
            "project_uuid": "project-uuid-1",
            "client_ip": "10.0.0.9",
        }

    def test_identity_fields_never_include_the_token(self, request_factory, bearer, token):
        assert token not in str(identity_fields(request_factory(bearer)))

    def test_identity_fields_are_empty_strings_when_anonymous(self, request_factory):
        fields = identity_fields(request_factory({}))
        assert fields["user_sub"] == ""
        assert fields["client_ip"] == "10.0.0.9"


class TestRateLimitKey:
    """Keying, as of 0.3.0: verified claims only, and no untrusted header.

    Peer in these tests is FakeRequest's default 10.0.0.9, so PEER_TRUSTED
    stands in for "the proxy is configured".
    """

    PEER_TRUSTED = ("10.0.0.0/8",)

    @staticmethod
    def _verified(req, payload):
        """Publish verified claims the way a verifying middleware would."""
        setattr(req.state, CLAIMS_STATE_ATTR, TokenClaims(payload, verified=True))
        return req

    def test_keys_on_sub_when_claims_are_verified(self, request_factory):
        req = self._verified(request_factory(), {"sub": "http://cilogon.org/serverA/users/12345"})
        assert rate_limit_key(req) == "http://cilogon.org/serverA/users/12345"

    def test_an_unverified_sub_is_ignored(self, request_factory, bearer):
        # The 0.3.0 change: this used to return the sub from an unverified
        # decode, which a caller can set to anything.
        assert rate_limit_key(request_factory(bearer)) == "10.0.0.9"

    def test_an_unverified_sub_is_used_when_explicitly_allowed(self, request_factory, bearer):
        assert (
            rate_limit_key(request_factory(bearer), require_verified=False)
            == "http://cilogon.org/serverA/users/12345"
        )

    def test_falls_back_to_ip_when_anonymous(self, request_factory):
        req = request_factory({"x-real-ip": "1.2.3.4"})
        assert rate_limit_key(req, trusted_proxies=self.PEER_TRUSTED) == "1.2.3.4"

    def test_falls_back_to_ip_for_undecodable_tokens(self, request_factory):
        req = request_factory({"authorization": "Bearer garbage", "x-real-ip": "1.2.3.4"})
        assert rate_limit_key(req, trusted_proxies=self.PEER_TRUSTED) == "1.2.3.4"

    def test_falls_back_when_the_chosen_claim_is_absent(self, request_factory):
        req = self._verified(request_factory({"x-real-ip": "1.2.3.4"}), {"email": "e@x.org"})
        assert rate_limit_key(req, trusted_proxies=self.PEER_TRUSTED) == "1.2.3.4"

    def test_claim_is_configurable(self, request_factory):
        req = self._verified(request_factory(), {"uuid": "user-uuid-1"})
        assert rate_limit_key(req, claim="uuid") == "user-uuid-1"

    def test_default_is_used_when_nothing_identifies_the_caller(self, request_factory):
        req = request_factory({}, client_host=None)
        assert rate_limit_key(req) == UNKNOWN_IP
        assert rate_limit_key(req, default="127.0.0.1") == "127.0.0.1"

    def test_default_is_ignored_when_a_claim_or_ip_is_present(self, request_factory):
        verified = self._verified(request_factory(), {"sub": "u"})
        assert rate_limit_key(verified, default="127.0.0.1") != "127.0.0.1"
        assert (
            rate_limit_key(
                request_factory({"x-real-ip": "1.2.3.4"}),
                trusted_proxies=self.PEER_TRUSTED,
                default="127.0.0.1",
            )
            == "1.2.3.4"
        )

    def test_socket_peer_still_beats_the_default(self, request_factory):
        assert rate_limit_key(request_factory({}), default="127.0.0.1") == "10.0.0.9"

    def test_key_is_stable_across_addresses_for_one_user(self, request_factory):
        a = self._verified(request_factory({"x-real-ip": "1.1.1.1"}), {"sub": "u"})
        b = self._verified(request_factory({"x-real-ip": "2.2.2.2"}), {"sub": "u"})
        assert rate_limit_key(a) == rate_limit_key(b)

    def test_an_untrusted_peer_cannot_assert_an_address(self, request_factory):
        # Without the peer in trusted_proxies the header carries no weight.
        req = request_factory({"x-real-ip": "1.2.3.4"})
        assert rate_limit_key(req) == "10.0.0.9"


class TestAuthFailureReason:
    def test_valid_token_is_not_a_failure(self, request_factory, bearer):
        assert auth_failure_reason(request_factory(bearer)) is None

    def test_malformed_header(self, request_factory):
        for value in ["Basic xyz", "Bearer", "Bearer ", "junk"]:
            req = request_factory({"authorization": value})
            assert auth_failure_reason(req) == REASON_MALFORMED_HEADER

    def test_missing_token_on_a_protected_path(self, request_factory):
        assert auth_failure_reason(request_factory({}, path="/mcp")) == REASON_MISSING_TOKEN

    def test_missing_token_on_an_open_path_is_not_a_failure(self, request_factory):
        assert auth_failure_reason(request_factory({}, path="/metrics")) is None

    def test_protected_prefixes_are_configurable(self, request_factory):
        req = request_factory({}, path="/api/v1/x")
        assert auth_failure_reason(req, protected_prefixes=("/api",)) == REASON_MISSING_TOKEN

    def test_undecodable_token(self, request_factory):
        req = request_factory({"authorization": "Bearer a.b.c"})
        assert auth_failure_reason(req) == REASON_INVALID_JWT

    def test_expired_token(self, request_factory, expired_token):
        req = request_factory({"authorization": f"Bearer {expired_token}"})
        assert auth_failure_reason(req) == REASON_EXPIRED_TOKEN

    def test_leeway_suppresses_marginal_expiry(self, request_factory, expired_token):
        req = request_factory({"authorization": f"Bearer {expired_token}"})
        assert auth_failure_reason(req, leeway=3600) is None

    def test_now_can_be_overridden(self, request_factory, token):
        req = request_factory({"authorization": f"Bearer {token}"})
        assert auth_failure_reason(req, now=time.time() + 86_400) == REASON_EXPIRED_TOKEN

    def test_token_without_exp_is_not_expired(self, request_factory):
        tok = make_token({"sub": "s"})
        assert auth_failure_reason(request_factory({"authorization": f"Bearer {tok}"})) is None
