"""Tests for Authorization header parsing and redaction."""
from __future__ import annotations

import pytest

from fabric_mcp_common.auth.bearer import (
    NO_TOKEN,
    REDACTED,
    STATE_ABSENT,
    STATE_MALFORMED,
    STATE_PRESENT,
    authorization_header,
    describe_authorization,
    extract_bearer_token,
    get_header,
    parse_authorization,
    redact_token,
)


class TestGetHeader:
    @pytest.mark.parametrize("name", ["authorization", "Authorization", "AUTHORIZATION"])
    def test_lookup_is_case_insensitive_on_both_sides(self, name):
        assert get_header({name: "v"}, "AuThOrIzAtIoN") == "v"

    def test_missing_and_empty_inputs(self):
        assert get_header({}, "authorization") is None
        assert get_header(None, "authorization") is None

    def test_non_mapping_input_does_not_raise(self):
        assert get_header(["not", "a", "mapping"], "authorization") is None


class TestParseAuthorization:
    def test_splits_scheme_and_credentials(self):
        assert parse_authorization("Bearer abc.def.ghi") == ("bearer", "abc.def.ghi")

    def test_tolerates_surrounding_and_inner_whitespace(self):
        assert parse_authorization("  Bearer   abc  ") == ("bearer", "abc")

    @pytest.mark.parametrize("value", [None, "", "   ", "Bearer", "Bearer ", "Bearer   "])
    def test_rejects_incomplete_values(self, value):
        assert parse_authorization(value) is None


class TestExtractBearerToken:
    def test_extracts_token(self, token):
        assert extract_bearer_token({"authorization": f"Bearer {token}"}) == token

    def test_scheme_matching_ignores_case(self, token):
        assert extract_bearer_token({"authorization": f"bEaReR {token}"}) == token

    def test_other_schemes_are_rejected(self):
        assert extract_bearer_token({"authorization": "Basic dXNlcjpwYXNz"}) is None

    def test_empty_credentials_yield_none(self):
        # Diverges (deliberately) from the original helper, which returned "".
        assert extract_bearer_token({"authorization": "Bearer "}) is None

    @pytest.mark.parametrize("headers", [None, {}, {"x-other": "v"}])
    def test_absent_header(self, headers):
        assert extract_bearer_token(headers) is None

    def test_custom_header_and_scheme(self, token):
        headers = {"x-fabric-token": f"Token {token}"}
        assert extract_bearer_token(headers, header_name="x-fabric-token", scheme="token") == token
        assert extract_bearer_token(headers) is None


class TestDescribeAuthorization:
    def test_absent(self):
        assert describe_authorization({}) == STATE_ABSENT
        assert describe_authorization({"authorization": "   "}) == STATE_ABSENT

    @pytest.mark.parametrize("value", ["Basic xyz", "Bearer", "Bearer ", "garbage"])
    def test_malformed(self, value):
        assert describe_authorization({"authorization": value}) == STATE_MALFORMED

    def test_present(self, token):
        assert describe_authorization({"authorization": f"Bearer {token}"}) == STATE_PRESENT


class TestRedaction:
    def test_default_hides_everything(self, token):
        assert redact_token(token) == REDACTED
        assert token not in redact_token(token)

    def test_keep_reveals_only_the_tail(self):
        out = redact_token("abcdefghijklmnop", keep=4)
        assert out == f"{REDACTED}mnop"

    def test_keep_is_ignored_for_short_tokens(self):
        assert redact_token("abcd", keep=4) == REDACTED

    @pytest.mark.parametrize("value", [None, ""])
    def test_absent_token_is_distinguishable(self, value):
        assert redact_token(value) == NO_TOKEN


def test_authorization_header_roundtrip(token):
    assert extract_bearer_token(authorization_header(token)) == token
