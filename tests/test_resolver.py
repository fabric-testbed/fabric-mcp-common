"""Tests for TokenResolver and AuthContext."""
from __future__ import annotations

import pytest

from fabric_mcp_common.auth.claims import TokenClaims
from fabric_mcp_common.auth.errors import (
    ExpiredTokenError,
    InvalidTokenError,
    MissingTokenError,
)
from fabric_mcp_common.auth.providers import (
    ChainTokenProvider,
    HeaderTokenProvider,
    StaticTokenProvider,
)
from fabric_mcp_common.auth.resolver import AuthContext, TokenResolver, TokenVerifier


class RecordingVerifier:
    """Verifier stub that records calls and returns canned results."""

    def __init__(self, claims=None, error=None):
        self._claims = claims
        self._error = error
        self.calls = []

    def verify(self, token):
        self.calls.append(token)
        if self._error is not None:
            raise self._error
        return self._claims


class TestTokenAccess:
    def test_token_passes_through_the_provider(self, token):
        assert TokenResolver(StaticTokenProvider(token)).token() == token

    def test_token_is_none_when_unauthenticated(self):
        assert TokenResolver(StaticTokenProvider(None)).token() is None

    def test_require_token_raises_when_absent(self):
        with pytest.raises(MissingTokenError, match="Authentication Required"):
            TokenResolver(StaticTokenProvider(None)).require_token()

    def test_require_token_does_not_warn(self, caplog):
        # The exception is the signal; the application owns warning-level
        # logging and its logger names. A library warning here would bypass
        # app log configuration and duplicate the app's own alerting line.
        import logging

        with caplog.at_level(logging.INFO, logger="fabric.common.auth"):
            with pytest.raises(MissingTokenError):
                TokenResolver(StaticTokenProvider(None)).require_token()
        assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []

    def test_missing_token_error_is_a_valueerror(self):
        # Existing FABRIC MCP call sites catch ValueError; keep that working.
        with pytest.raises(ValueError):
            TokenResolver(StaticTokenProvider(None)).require_token()


class TestClaims:
    def test_claims_decode_the_current_token(self, token):
        assert TokenResolver(StaticTokenProvider(token)).claims().email == "user@example.org"

    def test_claims_are_empty_and_never_raise_when_unauthenticated(self):
        claims = TokenResolver(StaticTokenProvider(None)).claims()
        assert isinstance(claims, TokenClaims)
        assert not claims

    def test_claims_are_empty_for_garbage_tokens(self):
        assert not TokenResolver(StaticTokenProvider("garbage")).claims()


class TestResolve:
    def test_returns_a_populated_context(self, token):
        ctx = TokenResolver(StaticTokenProvider(token)).resolve()
        assert isinstance(ctx, AuthContext)
        assert ctx.token == token
        assert ctx.identity == "user@example.org"
        assert ctx.user_uuid == "user-uuid-1"
        assert ctx.project_uuid == "project-uuid-1"
        assert ctx.source == "static"

    def test_source_reflects_the_winning_chain_member(self, token):
        chain = ChainTokenProvider(
            HeaderTokenProvider({}),
            StaticTokenProvider(token),
        )
        assert TokenResolver(chain).resolve().source == "static"

        chain = ChainTokenProvider(
            HeaderTokenProvider({"authorization": f"Bearer {token}"}),
            StaticTokenProvider("unused"),
        )
        assert TokenResolver(chain).resolve().source == "bearer"

    def test_raises_when_unauthenticated(self):
        with pytest.raises(MissingTokenError):
            TokenResolver(StaticTokenProvider(None)).resolve()

    def test_undecodable_token_still_resolves_without_verification(self):
        # Upstream is the authority on validity; the edge must not reject blindly.
        ctx = TokenResolver(StaticTokenProvider("garbage")).resolve()
        assert ctx.token == "garbage"
        assert not ctx.claims
        assert ctx.identity == "anonymous"


class TestExpiryEnforcement:
    def test_expired_tokens_pass_by_default(self, expired_token):
        assert TokenResolver(StaticTokenProvider(expired_token)).resolve().token == expired_token

    def test_expired_tokens_are_rejected_when_enforced(self, expired_token):
        resolver = TokenResolver(StaticTokenProvider(expired_token), enforce_expiry=True)
        with pytest.raises(ExpiredTokenError):
            resolver.resolve()

    def test_live_tokens_pass_when_enforced(self, token):
        assert TokenResolver(StaticTokenProvider(token), enforce_expiry=True).resolve()

    def test_leeway_admits_recently_expired_tokens(self, expired_token):
        resolver = TokenResolver(
            StaticTokenProvider(expired_token), enforce_expiry=True, leeway=3600
        )
        assert resolver.resolve().token == expired_token


class TestVerification:
    def test_verifier_supplies_the_claims(self, token):
        verified = TokenClaims({"sub": "verified-sub"}, verified=True)
        verifier = RecordingVerifier(claims=verified)
        ctx = TokenResolver(StaticTokenProvider(token), verifier=verifier).resolve()
        assert verifier.calls == [token]
        assert ctx.claims is verified
        assert ctx.verified is True

    def test_verification_is_on_by_default_when_a_verifier_is_given(self, token):
        verifier = RecordingVerifier(claims=TokenClaims({"sub": "s"}, verified=True))
        assert TokenResolver(StaticTokenProvider(token), verifier=verifier).verify is True

    def test_verifier_can_be_attached_but_disabled(self, token):
        verifier = RecordingVerifier(claims=TokenClaims({"sub": "s"}, verified=True))
        resolver = TokenResolver(StaticTokenProvider(token), verifier=verifier, verify=False)
        ctx = resolver.resolve()
        assert verifier.calls == []
        assert ctx.verified is False

    def test_verify_without_a_verifier_is_a_configuration_error(self):
        with pytest.raises(ValueError, match="requires a verifier"):
            TokenResolver(StaticTokenProvider("t"), verify=True)

    def test_verification_failures_propagate(self, token):
        verifier = RecordingVerifier(error=InvalidTokenError("bad signature"))
        with pytest.raises(InvalidTokenError, match="bad signature"):
            TokenResolver(StaticTokenProvider(token), verifier=verifier).resolve()

    def test_expiry_is_not_double_checked_when_verifying(self, expired_token):
        # The verifier owns expiry when enabled; no unverified re-check.
        verifier = RecordingVerifier(claims=TokenClaims({"sub": "s"}, verified=True))
        resolver = TokenResolver(
            StaticTokenProvider(expired_token), verifier=verifier, enforce_expiry=True
        )
        assert resolver.resolve().verified is True

    def test_recording_verifier_satisfies_the_protocol(self):
        assert isinstance(RecordingVerifier(), TokenVerifier)


class TestTryResolve:
    def test_returns_none_when_unauthenticated(self):
        assert TokenResolver(StaticTokenProvider(None)).try_resolve() is None

    def test_returns_a_context_when_authenticated(self, token):
        assert TokenResolver(StaticTokenProvider(token)).try_resolve().token == token

    def test_swallows_verification_failures(self, token):
        verifier = RecordingVerifier(error=InvalidTokenError("nope"))
        assert TokenResolver(StaticTokenProvider(token), verifier=verifier).try_resolve() is None

    def test_swallows_expiry_failures(self, expired_token):
        resolver = TokenResolver(StaticTokenProvider(expired_token), enforce_expiry=True)
        assert resolver.try_resolve() is None


class TestAuthContext:
    def test_log_fields_exclude_the_token(self, token):
        ctx = TokenResolver(StaticTokenProvider(token)).resolve()
        fields = ctx.log_fields()
        assert token not in str(fields)
        assert fields["user_email"] == "user@example.org"
        assert fields["auth_source"] == "static"

    def test_log_fields_are_empty_strings_not_none(self):
        ctx = AuthContext("t", TokenClaims())
        assert set(ctx.log_fields().values()) == {"", "unknown"}

    def test_authorization_header_is_forwardable(self, token):
        ctx = TokenResolver(StaticTokenProvider(token)).resolve()
        assert ctx.authorization_header() == {"authorization": f"Bearer {token}"}

    def test_repr_redacts_the_token(self, token):
        text = repr(TokenResolver(StaticTokenProvider(token)).resolve())
        assert token not in text
        assert "***" in text


class TestComposition:
    def test_with_provider_preserves_policy(self, token):
        base = TokenResolver(StaticTokenProvider(None), enforce_expiry=True, leeway=5)
        derived = base.with_provider(StaticTokenProvider(token))
        assert derived.enforce_expiry is True
        assert derived.leeway == 5
        assert derived.resolve().token == token

    def test_resolver_repr_is_safe(self, token):
        assert token not in repr(TokenResolver(StaticTokenProvider(token)))
