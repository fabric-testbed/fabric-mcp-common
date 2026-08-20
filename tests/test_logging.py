"""Tests for structured logging, level wiring, and the tool decorator factory."""
from __future__ import annotations

import json
import logging

import pytest

from fabric_mcp_common import LOGGER_NAMESPACE
from fabric_mcp_common.logging import (
    DEFAULT_EXTRA_FIELDS,
    JsonFormatter,
    REDACTED_VALUE,
    configure_logging,
    describe_configuration,
    make_tool_logger,
    sanitize_params,
)


@pytest.fixture
def restore_logging():
    """Snapshot and restore root logging state around a configure_logging call."""
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    saved = {
        name: (logging.getLogger(name).level, logging.getLogger(name).propagate)
        for name in (LOGGER_NAMESPACE, "myserver", "httpx", "uvicorn")
    }
    yield
    for h in list(root.handlers):
        root.removeHandler(h)
    for h in handlers:
        root.addHandler(h)
    root.setLevel(level)
    for name, (lvl, prop) in saved.items():
        logging.getLogger(name).setLevel(lvl)
        logging.getLogger(name).propagate = prop


class TestSanitizeParams:
    @pytest.mark.parametrize(
        "name",
        ["token", "id_token", "password", "api_key", "ssh_private_key",
         "client_secret", "credential", "authorization"],
    )
    def test_credential_bearing_names_are_redacted(self, name):
        assert sanitize_params({name: "s3cret"})[name] == REDACTED_VALUE

    def test_redaction_matches_case_insensitively(self):
        assert sanitize_params({"ID_TOKEN": "x"})["ID_TOKEN"] == REDACTED_VALUE

    def test_ordinary_params_pass_through(self):
        assert sanitize_params({"site": "STAR", "cores": 8}) == {"site": "STAR", "cores": 8}

    def test_framework_noise_is_dropped(self):
        assert "ctx" not in sanitize_params({"ctx": object(), "site": "STAR"})

    def test_long_strings_are_truncated_with_their_length(self):
        out = sanitize_params({"blob": "x" * 500})["blob"]
        assert out.startswith("x" * 200)
        assert "(500 chars)" in out

    def test_short_strings_are_untouched(self):
        assert sanitize_params({"s": "x" * 200})["s"] == "x" * 200

    def test_non_string_values_are_never_truncated(self):
        assert sanitize_params({"n": list(range(500))})["n"] == list(range(500))


class TestJsonFormatter:
    def _record(self, **extra):
        record = logging.LogRecord("l", logging.INFO, "f.py", 1, "hello %s", ("world",), None)
        for k, v in extra.items():
            setattr(record, k, v)
        return record

    def test_emits_the_base_fields(self):
        out = json.loads(JsonFormatter().format(self._record()))
        assert out["level"] == "INFO"
        assert out["logger"] == "l"
        assert out["msg"] == "hello world"
        assert out["ts"]

    def test_includes_present_extra_fields(self):
        out = json.loads(JsonFormatter().format(self._record(request_id="rid", tool="t")))
        assert out["request_id"] == "rid"
        assert out["tool"] == "t"

    def test_omits_absent_extra_fields(self):
        assert "request_id" not in json.loads(JsonFormatter().format(self._record()))

    @pytest.mark.parametrize("field", ["user_uuid", "project_name", "project_uuid"])
    def test_identity_fields_are_not_dropped(self, field):
        # An earlier field list omitted these, silently losing them in JSON mode.
        assert field in DEFAULT_EXTRA_FIELDS
        out = json.loads(JsonFormatter().format(self._record(**{field: "v"})))
        assert out[field] == "v"

    def test_exception_info_is_included(self):
        try:
            raise ValueError("boom")
        except ValueError:
            import sys

            record = self._record()
            record.exc_info = sys.exc_info()
        out = json.loads(JsonFormatter().format(record))
        assert "ValueError: boom" in out["exc_info"]

    def test_output_is_a_single_line(self):
        assert "\n" not in JsonFormatter().format(self._record(error="a\nb"))

    def test_non_serializable_values_do_not_raise(self):
        out = json.loads(JsonFormatter().format(self._record(result_size=object())))
        assert isinstance(out["result_size"], str)

    def test_unicode_is_preserved(self):
        record = logging.LogRecord("l", logging.INFO, "f", 1, "café ☕", (), None)
        assert "café ☕" in JsonFormatter().format(record)

    def test_extra_fields_are_configurable(self):
        out = json.loads(JsonFormatter(extra_fields=("custom",)).format(self._record(custom="c")))
        assert out["custom"] == "c"


class TestConfigureLogging:
    def test_installs_exactly_one_handler(self, restore_logging):
        configure_logging()
        assert len(logging.getLogger().handlers) == 1

    def test_repeated_calls_do_not_duplicate_handlers(self, restore_logging):
        configure_logging()
        configure_logging()
        assert len(logging.getLogger().handlers) == 1

    def test_library_namespace_honours_the_level(self, restore_logging):
        # Without this the package's own debug logs are unreachable, because the
        # root logger is deliberately clamped to WARNING.
        configure_logging(level="DEBUG")
        assert logging.getLogger(LOGGER_NAMESPACE).getEffectiveLevel() == logging.DEBUG

    def test_subloggers_inherit_the_namespace_level(self, restore_logging):
        configure_logging(level="DEBUG")
        for child in ("auth", "metrics", "tools", "something.added.later"):
            logger = logging.getLogger(f"{LOGGER_NAMESPACE}.{child}")
            assert logger.getEffectiveLevel() == logging.DEBUG

    def test_app_loggers_honour_the_level(self, restore_logging):
        configure_logging(level="DEBUG", app_loggers=("myserver",))
        assert logging.getLogger("myserver").getEffectiveLevel() == logging.DEBUG

    def test_root_is_held_at_warning(self, restore_logging):
        configure_logging(level="DEBUG")
        assert logging.getLogger().level == logging.WARNING

    def test_noisy_libraries_are_pinned(self, restore_logging):
        configure_logging(level="DEBUG")
        assert logging.getLogger("httpx").level == logging.WARNING

    def test_frameworks_are_pinned_to_info(self, restore_logging):
        configure_logging(level="DEBUG")
        assert logging.getLogger("uvicorn").level == logging.INFO

    def test_json_format_is_selectable(self, restore_logging):
        configure_logging(fmt="json")
        assert isinstance(logging.getLogger().handlers[0].formatter, JsonFormatter)

    def test_unknown_level_falls_back_to_info(self, restore_logging):
        configure_logging(level="NOPE")
        assert logging.getLogger(LOGGER_NAMESPACE).level == logging.INFO

    def test_stream_is_configurable(self, restore_logging):
        import io

        buf = io.StringIO()
        configure_logging(stream=buf, app_loggers=("myserver",))
        logging.getLogger("myserver").warning("to the buffer")
        assert "to the buffer" in buf.getvalue()

    def test_describe_configuration_summarizes_levels(self):
        assert "app_level=DEBUG" in describe_configuration("DEBUG")
        assert "root_level=WARNING" in describe_configuration("DEBUG")


class TestMakeToolLogger:
    @pytest.fixture
    def trace(self):
        return lambda: {
            "request_id": "rid-1",
            "user_sub": "s",
            "user_email": "u@x.org",
            "user_uuid": "uu",
            "project_name": "P",
            "client_ip": "1.2.3.4",
        }

    def _run(self, coro):
        import asyncio

        return asyncio.new_event_loop().run_until_complete(coro)

    def test_returns_the_wrapped_result(self, trace):
        tool_logger = make_tool_logger(trace_context=trace)

        @tool_logger("my_tool")
        async def my_tool(**kwargs):
            return {"count": 3}

        assert self._run(my_tool()) == {"count": 3}

    def test_preserves_function_metadata_for_fastmcp(self, trace):
        tool_logger = make_tool_logger(trace_context=trace)

        @tool_logger("my_tool")
        async def my_tool(a: int = 1) -> dict:
            """Docstring survives."""
            return {}

        assert my_tool.__name__ == "my_tool"
        assert my_tool.__doc__ == "Docstring survives."
        # PEP 563 is active in this module, so annotations are strings; the
        # point is that @wraps preserved them for FastMCP's schema generation.
        assert my_tool.__annotations__ == {"a": "int", "return": "dict"}

    def test_logs_start_and_done_with_identity(self, trace, caplog):
        tool_logger = make_tool_logger(logger="test.tools", trace_context=trace)

        @tool_logger("my_tool")
        async def my_tool():
            return []

        with caplog.at_level(logging.INFO, logger="test.tools"):
            self._run(my_tool())
        messages = [r.getMessage() for r in caplog.records]
        assert any(">>> START" in msg and "u@x.org" in msg for msg in messages)
        assert any("<<< DONE" in msg for msg in messages)
        assert all(r.request_id == "rid-1" for r in caplog.records)
        assert all(r.user_uuid == "uu" for r in caplog.records)

    def test_redacts_parameters_in_debug_line(self, trace, caplog):
        tool_logger = make_tool_logger(logger="test.tools", trace_context=trace)

        @tool_logger("my_tool")
        async def my_tool(**kwargs):
            return {}

        with caplog.at_level(logging.DEBUG, logger="test.tools"):
            self._run(my_tool(id_token="super-secret", site="STAR"))
        text = " ".join(r.getMessage() for r in caplog.records)
        assert "super-secret" not in text
        assert REDACTED_VALUE in text
        assert "STAR" in text

    def test_errors_are_logged_and_re_raised(self, trace, caplog):
        tool_logger = make_tool_logger(logger="test.tools", trace_context=trace)

        @tool_logger("my_tool")
        async def my_tool():
            raise RuntimeError("boom")

        with caplog.at_level(logging.ERROR, logger="test.tools"):
            with pytest.raises(RuntimeError, match="boom"):
                self._run(my_tool())
        assert any("!!! ERROR" in r.getMessage() for r in caplog.records)

    def test_generates_a_request_id_when_none_supplied(self):
        tool_logger = make_tool_logger(logger="test.tools", trace_context=lambda: {})
        seen = []

        @tool_logger("my_tool")
        async def my_tool():
            return {}

        import logging as _l

        handler = _l.Handler()
        handler.emit = lambda r: seen.append(r.request_id)
        log = _l.getLogger("test.tools")
        log.addHandler(handler)
        log.setLevel(_l.INFO)
        try:
            self._run(my_tool())
        finally:
            log.removeHandler(handler)
        assert all(rid and len(rid) == 12 for rid in seen)

    def test_trace_failures_do_not_break_the_tool(self):
        def exploding():
            raise RuntimeError("no request context")

        tool_logger = make_tool_logger(logger="test.tools", trace_context=exploding)

        @tool_logger("my_tool")
        async def my_tool():
            return "fine"

        assert self._run(my_tool()) == "fine"

    def test_metrics_are_recorded_when_enabled(self, trace):
        calls = []
        tool_logger = make_tool_logger(
            trace_context=trace, record_metrics=lambda **kw: calls.append(kw), metrics_enabled=True
        )

        @tool_logger("my_tool")
        async def my_tool():
            return {}

        self._run(my_tool())
        assert calls[0]["tool"] == "my_tool"
        assert calls[0]["status"] == "ok"
        assert calls[0]["user_uuid"] == "uu"
        assert calls[0]["duration_seconds"] >= 0

    def test_metrics_record_error_status(self, trace):
        calls = []
        tool_logger = make_tool_logger(
            trace_context=trace, record_metrics=lambda **kw: calls.append(kw), metrics_enabled=True
        )

        @tool_logger("my_tool")
        async def my_tool():
            raise ValueError("nope")

        with pytest.raises(ValueError):
            self._run(my_tool())
        assert calls[0]["status"] == "error"

    def test_metrics_are_off_by_default(self, trace):
        calls = []
        tool_logger = make_tool_logger(
            trace_context=trace, record_metrics=lambda **kw: calls.append(kw)
        )

        @tool_logger("my_tool")
        async def my_tool():
            return {}

        self._run(my_tool())
        assert calls == []

    def test_metrics_gate_is_evaluated_per_call(self, trace):
        enabled = {"on": False}
        calls = []
        tool_logger = make_tool_logger(
            trace_context=trace,
            record_metrics=lambda **kw: calls.append(kw),
            metrics_enabled=lambda: enabled["on"],
        )

        @tool_logger("my_tool")
        async def my_tool():
            return {}

        self._run(my_tool())
        enabled["on"] = True          # config read after import must be honoured
        self._run(my_tool())
        assert len(calls) == 1

    def test_metrics_failures_do_not_break_the_tool(self, trace):
        def exploding(**kwargs):
            raise RuntimeError("registry down")

        tool_logger = make_tool_logger(
            trace_context=trace, record_metrics=exploding, metrics_enabled=True
        )

        @tool_logger("my_tool")
        async def my_tool():
            return "fine"

        assert self._run(my_tool()) == "fine"

    @pytest.mark.parametrize(
        "result,expected",
        [([1, 2, 3], 3), ({"count": 7}, 7), ({"a": 1, "b": 2}, 2), ("str", None), (None, None)],
    )
    def test_result_size_reporting(self, trace, caplog, result, expected):
        tool_logger = make_tool_logger(logger="test.tools", trace_context=trace)

        @tool_logger("my_tool")
        async def my_tool():
            return result

        with caplog.at_level(logging.INFO, logger="test.tools"):
            self._run(my_tool())
        done = [r for r in caplog.records if "<<< DONE" in r.getMessage()][0]
        assert done.result_size == expected
