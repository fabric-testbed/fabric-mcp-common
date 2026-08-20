"""Tests for unverified claim decoding."""
from __future__ import annotations

import time

import pytest

from conftest import b64url, make_token
from fabric_mcp_common.auth.claims import (
    ANONYMOUS,
    LEGACY_CLAIM_KEYS,
    TokenClaims,
    decode_payload,
    decode_token_claims,
)
from fabric_mcp_common.auth.errors import InvalidTokenError


class TestDecodePayload:
    def test_decodes_unpadded_base64url(self, token, payload):
        assert decode_payload(token) == payload

    def test_decodes_payload_needing_each_padding_length(self):
        # Exercise all three padding remainders (len % 4 in {2, 3, 0}).
        for filler in ("a", "ab", "abc", "abcd"):
            tok = make_token({"sub": filler})
            assert decode_payload(tok) == {"sub": filler}

    def test_handles_non_ascii_claims(self):
        tok = make_token({"name": "Ünïcødé Nâme"})
        assert decode_payload(tok)["name"] == "Ünïcødé Nâme"

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "not-a-jwt",
            "only.two",
            "a.b.c.d.e",
            "header.!!!not-base64!!!.sig",
            None,
            12345,
        ],
    )
    def test_malformed_input_returns_empty_by_default(self, bad):
        assert decode_payload(bad) == {}

    @pytest.mark.parametrize("bad", ["", "only.two", "a.b.c.d.e", "h.!!!.s"])
    def test_strict_mode_raises(self, bad):
        with pytest.raises(InvalidTokenError):
            decode_payload(bad, strict=True)

    def test_non_object_payload_is_rejected(self):
        tok = f"{b64url({'alg': 'none'})}.{b64url([1, 2, 3])}.sig"
        assert decode_payload(tok) == {}
        with pytest.raises(InvalidTokenError):
            decode_payload(tok, strict=True)


class TestTokenClaimsIdentity:
    def test_exposes_identity_claims(self, token, payload):
        claims = TokenClaims.from_token(token)
        assert claims.sub == payload["sub"]
        assert claims.email == payload["email"]
        assert claims.name == payload["name"]
        assert claims.uuid == payload["uuid"]
        assert claims.iss == payload["iss"]
        assert claims.aud == payload["aud"]

    def test_derives_first_project(self, token):
        claims = TokenClaims.from_token(token)
        assert claims.project_name == "Project One"
        assert claims.project_uuid == "project-uuid-1"
        assert len(claims.projects) == 2

    def test_projects_claim_of_wrong_shape_is_ignored(self):
        for projects in ("nope", 42, [], [None], ["str"]):
            claims = TokenClaims.from_token(make_token({"projects": projects}))
            assert claims.project_name is None
            assert claims.project_uuid is None

    def test_project_without_uuid_still_yields_name(self):
        claims = TokenClaims.from_token(make_token({"projects": [{"name": "P"}]}))
        assert claims.project_name == "P"
        assert claims.project_uuid is None

    def test_identity_prefers_email_then_name_then_sub_then_uuid(self):
        assert TokenClaims({"email": "e", "name": "n", "sub": "s"}).identity() == "e"
        assert TokenClaims({"name": "n", "sub": "s"}).identity() == "n"
        assert TokenClaims({"sub": "s", "uuid": "u"}).identity() == "s"
        assert TokenClaims({"uuid": "u"}).identity() == "u"

    def test_identity_falls_back_to_anonymous(self):
        assert TokenClaims().identity() == ANONYMOUS
        assert TokenClaims().identity("nobody") == "nobody"


class TestTokenClaimsMapping:
    def test_supports_mapping_access(self, token, payload):
        claims = TokenClaims.from_token(token)
        assert claims.get("sub") == payload["sub"]
        assert claims["email"] == payload["email"]
        assert "uuid" in claims
        assert claims.get("nope") is None
        assert claims.get("nope", "dflt") == "dflt"

    def test_derived_claims_are_visible_through_mapping(self, token):
        claims = TokenClaims.from_token(token)
        assert claims.get("project_name") == "Project One"
        assert "project_uuid" in claims
        assert "project_name" in set(claims.keys())

    def test_iteration_does_not_duplicate_keys(self, token):
        claims = TokenClaims.from_token(token)
        keys = list(claims)
        assert len(keys) == len(set(keys)) == len(claims)

    def test_empty_claims_are_falsy(self):
        assert not TokenClaims()
        assert not TokenClaims.from_token("garbage")
        assert not TokenClaims.from_token(None)
        assert len(TokenClaims()) == 0

    def test_populated_claims_are_truthy(self, token):
        assert TokenClaims.from_token(token)

    def test_equality_against_claims_and_plain_dicts(self):
        assert TokenClaims({"sub": "s"}) == TokenClaims({"sub": "s"})
        assert TokenClaims({"sub": "s"}) != TokenClaims({"sub": "other"})
        assert TokenClaims({"sub": "s"}) == {"sub": "s"}
        assert TokenClaims({"sub": "s"}) != "not a mapping"

    def test_raw_and_to_dict_are_copies(self, token):
        claims = TokenClaims.from_token(token)
        claims.raw["sub"] = "mutated"
        claims.to_dict()["sub"] = "mutated"
        assert claims.sub != "mutated"

    def test_raw_excludes_derived_claims(self, token):
        assert "project_name" not in TokenClaims.from_token(token).raw

    def test_repr_shows_identity_not_payload(self, token):
        text = repr(TokenClaims.from_token(token))
        assert "user@example.org" in text
        assert "cilogon.org/serverA" not in text


class TestExpiry:
    def test_reports_remaining_lifetime(self):
        claims = TokenClaims({"exp": 1_000_100})
        assert claims.expires_in(now=1_000_000) == 100
        assert claims.expires_in(now=1_000_200) == -100

    def test_expired_token_is_detected(self, expired_token):
        assert TokenClaims.from_token(expired_token).is_expired()

    def test_live_token_is_not_expired(self, token):
        assert not TokenClaims.from_token(token).is_expired()

    def test_leeway_tolerates_clock_skew(self):
        claims = TokenClaims({"exp": 1_000_000})
        assert claims.is_expired(now=1_000_030)
        assert not claims.is_expired(leeway=60, now=1_000_030)

    def test_missing_exp_is_not_treated_as_expired(self):
        claims = TokenClaims({"sub": "s"})
        assert not claims.is_expired()
        assert claims.expires_in() is None
        assert claims.exp is None

    @pytest.mark.parametrize(
        "value,expected",
        [(123, 123), ("123", 123), (123.9, 123), (True, None), ("nope", None), (None, None)],
    )
    def test_exp_coercion(self, value, expected):
        assert TokenClaims({"exp": value}).exp == expected

    def test_expiry_uses_wall_clock_when_now_omitted(self):
        assert TokenClaims({"exp": int(time.time()) - 1}).is_expired()


class TestLegacyCompatibility:
    def test_returns_only_legacy_keys(self, token):
        legacy = decode_token_claims(token)
        assert set(legacy) <= set(LEGACY_CLAIM_KEYS)
        assert legacy == {
            "sub": "http://cilogon.org/serverA/users/12345",
            "email": "user@example.org",
            "name": "Test User",
            "uuid": "user-uuid-1",
            "project_name": "Project One",
            "project_uuid": "project-uuid-1",
        }

    def test_omits_absent_keys_rather_than_nulling_them(self):
        assert decode_token_claims(make_token({"sub": "s"})) == {"sub": "s"}

    @pytest.mark.parametrize("bad", ["", "garbage", "a.b", "a.b.c.d"])
    def test_never_raises_on_bad_input(self, bad):
        assert decode_token_claims(bad) == {}

    def test_does_not_leak_non_identity_claims(self, token):
        assert "exp" not in decode_token_claims(token)


class TestVerifiedFlag:
    def test_unverified_by_default(self, token):
        assert TokenClaims.from_token(token).verified is False

    def test_flag_is_explicit(self):
        assert TokenClaims({"sub": "s"}, verified=True).verified is True

    def test_from_token_never_marks_verified(self, token):
        # from_token performs no signature check; it must never claim otherwise.
        assert not TokenClaims.from_token(token).verified


def test_from_token_strict_rejects_none():
    with pytest.raises(InvalidTokenError):
        TokenClaims.from_token(None, strict=True)


def test_empty_constructor_helper():
    assert TokenClaims.empty() == TokenClaims()
