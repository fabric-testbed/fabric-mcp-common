"""Tests for JWKS verification, with fss_utils stubbed out."""
from __future__ import annotations

import enum
import sys
import types
from datetime import timedelta

import pytest

from fabric_mcp_common.auth.errors import (
    ExpiredTokenError,
    InvalidTokenError,
    VerificationUnavailableError,
)
from fabric_mcp_common.auth.verify import (
    CERTS_PATH,
    DEFAULT_CREDMGR_HOST,
    CredMgrVerifier,
    credmgr_jwks_url,
    verify_token,
)


class ValidateCode(enum.Enum):
    """Mirror of ``fss_utils.jwt_manager.ValidateCode``."""

    VALID = 1
    UNSPECIFIED_KEY = 2
    UNSPECIFIED_ALG = 3
    UNKNOWN_KEY = 4
    INVALID = 5
    UNABLE_TO_FETCH_KEYS = 6
    UNPARSABLE_TOKEN = 7
    UNABLE_TO_DECODE_KEYS = 8
    UNABLE_TO_LOAD_KEYS = 9

    def interpret(self, exception=None):
        return f"{self.name}({exception})" if exception else self.name


class FakeExpiredSignatureError(Exception):
    pass


# PyJWT identifies expiry by exception type; the wrapper matches on the name too.
FakeExpiredSignatureError.__name__ = "ExpiredSignatureError"


@pytest.fixture
def fake_fss(monkeypatch):
    """Install a stub ``fss_utils.jwt_validate`` module.

    Returns a control dict: ``result`` is the ``(code, payload_or_exception)``
    tuple the validator returns; ``calls`` records each ``validate_jwt`` call.
    """
    control = {"result": (ValidateCode.VALID, {"sub": "s"}), "calls": [], "instances": []}

    class JWTValidator:
        def __init__(self, *, url, refresh_period, audience=None):
            self.url = url
            self.refresh_period = refresh_period
            self.audience = audience
            self.keysFetched = "sentinel"
            control["instances"].append(self)

        def validate_jwt(self, *, token, verify_exp=False):
            control["calls"].append({"token": token, "verify_exp": verify_exp})
            return control["result"]

    mod = types.ModuleType("fss_utils.jwt_validate")
    mod.JWTValidator = JWTValidator
    pkg = types.ModuleType("fss_utils")
    pkg.jwt_validate = mod
    monkeypatch.setitem(sys.modules, "fss_utils", pkg)
    monkeypatch.setitem(sys.modules, "fss_utils.jwt_validate", mod)
    return control


@pytest.fixture
def no_fss(monkeypatch):
    for name in ("fss_utils", "fss_utils.jwt_validate"):
        monkeypatch.setitem(sys.modules, name, None)


class TestJwksUrl:
    def test_default_host(self):
        assert credmgr_jwks_url() == f"https://{DEFAULT_CREDMGR_HOST}{CERTS_PATH}"

    def test_bare_host_gets_https(self):
        assert credmgr_jwks_url("cm.example.org") == f"https://cm.example.org{CERTS_PATH}"

    def test_explicit_scheme_is_preserved(self):
        assert credmgr_jwks_url("http://localhost:8443") == f"http://localhost:8443{CERTS_PATH}"

    def test_trailing_slash_and_whitespace_are_trimmed(self):
        assert credmgr_jwks_url("  cm.example.org/  ") == f"https://cm.example.org{CERTS_PATH}"


class TestVerifierConfiguration:
    def test_builds_the_url_from_the_host(self, fake_fss):
        CredMgrVerifier(credmgr_host="cm.example.org").verify("t")
        assert fake_fss["instances"][0].url == f"https://cm.example.org{CERTS_PATH}"

    def test_explicit_jwks_url_wins(self, fake_fss):
        CredMgrVerifier(jwks_url="https://x/keys", credmgr_host="ignored").verify("t")
        assert fake_fss["instances"][0].url == "https://x/keys"

    def test_audience_and_refresh_period_are_forwarded(self, fake_fss):
        CredMgrVerifier(audience="cilogon:/client_id/1", refresh_period=timedelta(minutes=5)).verify("t")
        inst = fake_fss["instances"][0]
        assert inst.audience == "cilogon:/client_id/1"
        assert inst.refresh_period == timedelta(minutes=5)

    def test_expiry_is_enforced_by_default(self, fake_fss):
        CredMgrVerifier().verify("t")
        assert fake_fss["calls"][0]["verify_exp"] is True

    def test_expiry_enforcement_can_be_disabled(self, fake_fss):
        CredMgrVerifier(verify_exp=False).verify("t")
        assert fake_fss["calls"][0]["verify_exp"] is False

    def test_validator_is_built_once_and_reused(self, fake_fss):
        verifier = CredMgrVerifier()
        verifier.verify("a")
        verifier.verify("b")
        assert len(fake_fss["instances"]) == 1
        assert [c["token"] for c in fake_fss["calls"]] == ["a", "b"]

    def test_validator_is_not_built_until_first_use(self, fake_fss):
        CredMgrVerifier()
        assert fake_fss["instances"] == []


class TestVerifySuccess:
    def test_returns_verified_claims(self, fake_fss, payload):
        fake_fss["result"] = (ValidateCode.VALID, payload)
        claims = CredMgrVerifier().verify("t")
        assert claims.verified is True
        assert claims.email == "user@example.org"
        assert claims.project_uuid == "project-uuid-1"

    def test_one_shot_helper(self, fake_fss, payload):
        fake_fss["result"] = (ValidateCode.VALID, payload)
        assert verify_token("t", credmgr_host="cm.example.org").sub == payload["sub"]


class TestVerifyFailure:
    @pytest.mark.parametrize(
        "code",
        [
            ValidateCode.INVALID,
            ValidateCode.UNPARSABLE_TOKEN,
            ValidateCode.UNSPECIFIED_KEY,
            ValidateCode.UNSPECIFIED_ALG,
            ValidateCode.UNKNOWN_KEY,
        ],
    )
    def test_bad_tokens_raise_invalid(self, fake_fss, code):
        fake_fss["result"] = (code, Exception("boom"))
        with pytest.raises(InvalidTokenError) as excinfo:
            CredMgrVerifier().verify("t")
        assert code.name in str(excinfo.value)

    @pytest.mark.parametrize(
        "code",
        [
            ValidateCode.UNABLE_TO_FETCH_KEYS,
            ValidateCode.UNABLE_TO_DECODE_KEYS,
            ValidateCode.UNABLE_TO_LOAD_KEYS,
        ],
    )
    def test_key_problems_are_server_faults_not_bad_credentials(self, fake_fss, code):
        fake_fss["result"] = (code, None)
        with pytest.raises(VerificationUnavailableError) as excinfo:
            CredMgrVerifier().verify("t")
        assert excinfo.value.error_type == "server_error"

    def test_expired_signature_is_distinguished_from_invalid(self, fake_fss):
        fake_fss["result"] = (ValidateCode.INVALID, FakeExpiredSignatureError("expired"))
        with pytest.raises(ExpiredTokenError):
            CredMgrVerifier().verify("t")

    def test_expired_is_still_an_invalid_token_error(self, fake_fss):
        fake_fss["result"] = (ValidateCode.INVALID, FakeExpiredSignatureError("expired"))
        with pytest.raises(InvalidTokenError):
            CredMgrVerifier().verify("t")

    @pytest.mark.parametrize("token", ["", None])
    def test_empty_token_is_rejected_without_calling_out(self, fake_fss, token):
        with pytest.raises(InvalidTokenError):
            CredMgrVerifier().verify(token)
        assert fake_fss["calls"] == []

    def test_missing_extra_reports_how_to_install_it(self, no_fss):
        with pytest.raises(VerificationUnavailableError, match=r"fabric-mcp-common\[verify\]"):
            CredMgrVerifier().verify("t")

    def test_all_failures_are_valueerrors(self, fake_fss):
        fake_fss["result"] = (ValidateCode.INVALID, Exception("boom"))
        with pytest.raises(ValueError):
            CredMgrVerifier().verify("t")


class TestRefreshKeys:
    def test_clears_the_cached_key_timestamp(self, fake_fss):
        verifier = CredMgrVerifier()
        verifier.verify("t")
        assert fake_fss["instances"][0].keysFetched == "sentinel"
        verifier.refresh_keys()
        assert fake_fss["instances"][0].keysFetched is None

    def test_is_safe_before_first_use(self, fake_fss):
        CredMgrVerifier().refresh_keys()
        assert fake_fss["instances"] == []


class TestResolverIntegration:
    def test_verifier_plugs_into_the_resolver(self, fake_fss, payload):
        from fabric_mcp_common.auth.providers import StaticTokenProvider
        from fabric_mcp_common.auth.resolver import TokenResolver

        fake_fss["result"] = (ValidateCode.VALID, payload)
        resolver = TokenResolver(StaticTokenProvider("t"), verifier=CredMgrVerifier())
        ctx = resolver.resolve()
        assert ctx.verified is True
        assert ctx.identity == "user@example.org"

    def test_verifier_satisfies_the_protocol(self):
        from fabric_mcp_common.auth.resolver import TokenVerifier

        assert isinstance(CredMgrVerifier(), TokenVerifier)
