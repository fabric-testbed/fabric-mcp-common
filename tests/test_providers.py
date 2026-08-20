"""Tests for token sources."""
from __future__ import annotations

import json
import os

import pytest

from fabric_mcp_common.auth.errors import MissingTokenError, TokenSourceError
from fabric_mcp_common.auth.providers import (
    TOKEN_ENV,
    TOKEN_LOCATION_ENV,
    CallableTokenProvider,
    ChainTokenProvider,
    EnvTokenProvider,
    FileTokenProvider,
    HeaderTokenProvider,
    StaticTokenProvider,
    TokenProvider,
    read_token_from_file,
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    monkeypatch.delenv(TOKEN_LOCATION_ENV, raising=False)
    monkeypatch.delenv(TOKEN_ENV, raising=False)


class TestStaticProvider:
    def test_returns_token(self):
        assert StaticTokenProvider("t").get_token() == "t"

    @pytest.mark.parametrize("value", [None, ""])
    def test_empty_normalizes_to_none(self, value):
        assert StaticTokenProvider(value).get_token() is None

    def test_satisfies_the_protocol(self):
        assert isinstance(StaticTokenProvider("t"), TokenProvider)

    def test_repr_never_contains_the_token(self):
        assert "secret" not in repr(StaticTokenProvider("secret"))

    def test_require_token_raises_when_absent(self):
        with pytest.raises(MissingTokenError):
            StaticTokenProvider(None).require_token()


class TestEnvProvider:
    def test_reads_and_strips_the_variable(self, monkeypatch):
        monkeypatch.setenv(TOKEN_ENV, "  tok  ")
        assert EnvTokenProvider().get_token() == "tok"

    def test_absent_or_blank_yields_none(self, monkeypatch):
        assert EnvTokenProvider().get_token() is None
        monkeypatch.setenv(TOKEN_ENV, "   ")
        assert EnvTokenProvider().get_token() is None

    def test_resolves_lazily_so_later_env_changes_are_seen(self, monkeypatch):
        provider = EnvTokenProvider()
        assert provider.get_token() is None
        monkeypatch.setenv(TOKEN_ENV, "late")
        assert provider.get_token() == "late"


class TestFileProvider:
    def test_reads_id_token_object(self, tmp_path):
        p = tmp_path / "tok.json"
        p.write_text(json.dumps({"id_token": "abc", "refresh_token": "zzz"}))
        assert FileTokenProvider(p).get_token() == "abc"

    def test_reads_json_string_file(self, tmp_path):
        p = tmp_path / "tok.json"
        p.write_text(json.dumps("abc"))
        assert FileTokenProvider(p).get_token() == "abc"

    def test_reads_bare_jwt_file(self, tmp_path, token):
        p = tmp_path / "tok"
        p.write_text(f"{token}\n")
        assert FileTokenProvider(p).get_token() == token

    def test_honours_key_precedence(self, tmp_path):
        p = tmp_path / "tok.json"
        p.write_text(json.dumps({"access_token": "second", "id_token": "first"}))
        assert FileTokenProvider(p).get_token() == "first"

    def test_custom_keys(self, tmp_path):
        p = tmp_path / "tok.json"
        p.write_text(json.dumps({"custom": "c"}))
        assert FileTokenProvider(p, keys=("custom",)).get_token() == "c"

    def test_resolves_path_from_env(self, tmp_path, monkeypatch):
        p = tmp_path / "tok.json"
        p.write_text(json.dumps({"id_token": "abc"}))
        monkeypatch.setenv(TOKEN_LOCATION_ENV, str(p))
        assert FileTokenProvider().get_token() == "abc"

    def test_explicit_path_beats_env(self, tmp_path, monkeypatch):
        (tmp_path / "a.json").write_text(json.dumps({"id_token": "explicit"}))
        (tmp_path / "b.json").write_text(json.dumps({"id_token": "env"}))
        monkeypatch.setenv(TOKEN_LOCATION_ENV, str(tmp_path / "b.json"))
        assert FileTokenProvider(tmp_path / "a.json").get_token() == "explicit"

    def test_expands_user_in_env_path(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        (tmp_path / "tok.json").write_text(json.dumps({"id_token": "abc"}))
        monkeypatch.setenv(TOKEN_LOCATION_ENV, "~/tok.json")
        assert FileTokenProvider().get_token() == "abc"

    def test_strict_mode_raises_when_env_unset(self):
        with pytest.raises(TokenSourceError, match=f"{TOKEN_LOCATION_ENV} environment variable"):
            FileTokenProvider().get_token()

    def test_non_strict_mode_returns_none_when_unconfigured(self):
        assert FileTokenProvider(strict=False).get_token() is None

    def test_strict_mode_raises_on_missing_file(self, tmp_path):
        with pytest.raises(TokenSourceError, match="Failed to read token"):
            FileTokenProvider(tmp_path / "nope.json").get_token()

    def test_non_strict_mode_swallows_missing_file(self, tmp_path):
        assert FileTokenProvider(tmp_path / "nope.json", strict=False).get_token() is None

    @pytest.mark.parametrize("content", ["", "   ", "{not json", json.dumps({"other": "x"}), "[]"])
    def test_unusable_content_raises_in_strict_mode(self, tmp_path, content):
        p = tmp_path / "tok.json"
        p.write_text(content)
        with pytest.raises(TokenSourceError):
            FileTokenProvider(p).get_token()

    def test_unusable_content_yields_none_in_non_strict_mode(self, tmp_path):
        p = tmp_path / "tok.json"
        p.write_text("{not json")
        assert FileTokenProvider(p, strict=False).get_token() is None

    def test_errors_name_the_path(self, tmp_path):
        p = tmp_path / "tok.json"
        p.write_text("{not json")
        with pytest.raises(TokenSourceError, match=str(p)):
            FileTokenProvider(p).get_token()

    def test_rereads_after_the_file_changes(self, tmp_path):
        p = tmp_path / "tok.json"
        p.write_text(json.dumps({"id_token": "first"}))
        provider = FileTokenProvider(p)
        assert provider.get_token() == "first"

        # Force a distinct mtime/size so the cache stamp differs.
        p.write_text(json.dumps({"id_token": "second-token"}))
        os.utime(p, (0, 0))
        assert provider.get_token() == "second-token"

    def test_cache_avoids_rereading_unchanged_files(self, tmp_path, count_opens):
        p = tmp_path / "tok.json"
        p.write_text(json.dumps({"id_token": "abc"}))
        provider = FileTokenProvider(p)

        with count_opens() as opens:
            assert provider.get_token() == "abc"
            assert provider.get_token() == "abc"
            assert provider.get_token() == "abc"
        assert len(opens) == 1

    def test_caching_can_be_disabled(self, tmp_path, count_opens):
        p = tmp_path / "tok.json"
        p.write_text(json.dumps({"id_token": "abc"}))
        provider = FileTokenProvider(p, cache=False)

        with count_opens() as opens:
            provider.get_token()
            provider.get_token()
        assert len(opens) == 2

    def test_refresh_forces_a_reread(self, tmp_path, count_opens):
        p = tmp_path / "tok.json"
        p.write_text(json.dumps({"id_token": "abc"}))
        provider = FileTokenProvider(p)
        provider.get_token()

        with count_opens() as opens:
            provider.refresh()
            assert provider.get_token() == "abc"
        assert len(opens) == 1

    def test_path_property_reflects_configuration(self, tmp_path, monkeypatch):
        assert FileTokenProvider().path is None
        monkeypatch.setenv(TOKEN_LOCATION_ENV, str(tmp_path / "x.json"))
        assert FileTokenProvider().path == str(tmp_path / "x.json")

    def test_repr_shows_path_only(self, tmp_path):
        text = repr(FileTokenProvider(tmp_path / "x.json"))
        assert "x.json" in text


class TestCallableProvider:
    def test_delegates_to_the_callable(self):
        assert CallableTokenProvider(lambda: "t").get_token() == "t"

    def test_called_on_every_access(self):
        seq = iter(["a", "b"])
        provider = CallableTokenProvider(lambda: next(seq))
        assert provider.get_token() == "a"
        assert provider.get_token() == "b"

    def test_source_label_can_be_overridden(self):
        assert CallableTokenProvider(lambda: "t", source="vault").source == "vault"

    def test_rejects_non_callables(self):
        with pytest.raises(TypeError):
            CallableTokenProvider("not-callable")


class TestHeaderProvider:
    def test_reads_from_a_static_mapping(self, token):
        provider = HeaderTokenProvider({"authorization": f"Bearer {token}"})
        assert provider.get_token() == token

    def test_reads_from_a_callable_per_call(self, token):
        current = {}
        provider = HeaderTokenProvider(lambda: current)
        assert provider.get_token() is None
        current["Authorization"] = f"Bearer {token}"
        assert provider.get_token() == token

    def test_callable_returning_none_is_tolerated(self):
        assert HeaderTokenProvider(lambda: None).get_token() is None

    def test_custom_header_and_scheme(self, token):
        provider = HeaderTokenProvider(
            {"x-token": f"Token {token}"}, header_name="x-token", scheme="token"
        )
        assert provider.get_token() == token


class TestChainProvider:
    def test_first_match_wins(self):
        chain = ChainTokenProvider(StaticTokenProvider(None), StaticTokenProvider("second"))
        assert chain.get_token() == "second"

    def test_records_the_winning_source(self, token):
        chain = ChainTokenProvider(
            HeaderTokenProvider({}), StaticTokenProvider("t")
        )
        assert chain.get_token() == "t"
        assert chain.last_source == "static"

    def test_last_source_resets_when_nothing_matches(self):
        chain = ChainTokenProvider(StaticTokenProvider("t"))
        chain.get_token()
        chain.providers = (StaticTokenProvider(None),)
        assert chain.get_token() is None
        assert chain.last_source is None

    def test_empty_chain_yields_none(self):
        assert ChainTokenProvider().get_token() is None

    def test_none_members_are_dropped(self):
        chain = ChainTokenProvider(None, StaticTokenProvider("t"))
        assert chain.get_token() == "t"

    def test_nested_chains_are_flattened(self):
        inner = ChainTokenProvider(StaticTokenProvider(None), StaticTokenProvider("t"))
        outer = ChainTokenProvider(inner, StaticTokenProvider("other"))
        assert len(outer.providers) == 3
        assert outer.get_token() == "t"

    def test_source_errors_are_skipped_by_default(self):
        chain = ChainTokenProvider(FileTokenProvider(), StaticTokenProvider("fallback"))
        assert chain.get_token() == "fallback"

    def test_source_errors_propagate_when_requested(self):
        chain = ChainTokenProvider(
            FileTokenProvider(), StaticTokenProvider("fallback"), skip_source_errors=False
        )
        with pytest.raises(TokenSourceError):
            chain.get_token()

    def test_repr_never_contains_token_material(self):
        assert "secret" not in repr(ChainTokenProvider(StaticTokenProvider("secret")))


class TestReadTokenFromFileCompat:
    def test_reads_id_token(self, tmp_path, monkeypatch):
        p = tmp_path / "tok.json"
        p.write_text(json.dumps({"id_token": "abc"}))
        monkeypatch.setenv(TOKEN_LOCATION_ENV, str(p))
        assert read_token_from_file() == "abc"

    def test_accepts_an_explicit_path(self, tmp_path):
        p = tmp_path / "tok.json"
        p.write_text(json.dumps({"id_token": "abc"}))
        assert read_token_from_file(p) == "abc"

    def test_errors_are_valueerrors_for_legacy_callers(self):
        with pytest.raises(ValueError, match="environment variable is not set"):
            read_token_from_file()

    def test_unreadable_file_message_matches_legacy_format(self, tmp_path, monkeypatch):
        monkeypatch.setenv(TOKEN_LOCATION_ENV, str(tmp_path / "nope.json"))
        with pytest.raises(ValueError, match="Failed to read token from"):
            read_token_from_file()

    def test_unexpected_format_message_matches_legacy_format(self, tmp_path):
        p = tmp_path / "tok.json"
        p.write_text(json.dumps({"nothing": "here"}))
        with pytest.raises(ValueError, match="Unexpected token format in"):
            read_token_from_file(p)
