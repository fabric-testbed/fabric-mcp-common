"""
Token sources.

A :class:`TokenProvider` answers one question — "what is the caller's token
right now?" — and hides *where* it came from.  That indirection is what lets a
single tool implementation serve both deployment modes FABRIC MCP servers run
in: a long-lived local process reading a token file, and an HTTP server reading
a per-request ``Authorization`` header.

Providers are cheap to construct and resolve their source lazily on every
:meth:`TokenProvider.get_token` call, so environment changes and rotated token
files are picked up without restarting.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence, Tuple, Union

try:  # pragma: no cover - typing_extensions fallback for older interpreters
    from typing import Protocol, runtime_checkable
except ImportError:  # pragma: no cover
    from typing_extensions import Protocol, runtime_checkable  # type: ignore

from fabric_mcp_common.auth.bearer import (
    AUTHORIZATION_HEADER,
    BEARER_SCHEME,
    extract_bearer_token,
)
from fabric_mcp_common.auth.errors import MissingTokenError, TokenSourceError

log = logging.getLogger("fabric.common.auth")

#: Environment variable naming the FABRIC token file.
TOKEN_LOCATION_ENV = "FABRIC_TOKEN_LOCATION"

#: Environment variable holding a bare token value.
TOKEN_ENV = "FABRIC_ID_TOKEN"

#: JSON keys searched, in order, when a token file contains an object.
DEFAULT_TOKEN_KEYS: Tuple[str, ...] = ("id_token", "token", "access_token")

#: Header value or a zero-argument callable returning one.
HeadersLike = Union[Mapping[str, str], Callable[[], Optional[Mapping[str, str]]]]


@runtime_checkable
class TokenProvider(Protocol):
    """Anything that can supply a token string."""

    def get_token(self) -> Optional[str]:
        """Return the current token, or ``None`` when this source has none."""
        ...


class BaseTokenProvider:
    """Shared behaviour for the concrete providers in this module."""

    #: Short label identifying the provider kind, propagated to
    #: :attr:`fabric_mcp_common.auth.resolver.AuthContext.source`.
    source: str = "unknown"

    def get_token(self) -> Optional[str]:  # pragma: no cover - abstract
        raise NotImplementedError

    def require_token(self) -> str:
        """Return the token, raising when this source has none.

        Raises:
            MissingTokenError: If :meth:`get_token` yields nothing.
        """
        token = self.get_token()
        if not token:
            raise MissingTokenError()
        return token

    def __repr__(self) -> str:
        # Never interpolate token material into a repr.
        return f"{type(self).__name__}(source={self.source!r})"


class StaticTokenProvider(BaseTokenProvider):
    """Serves a token supplied up front.

    Useful in tests, CLI entry points, and any place the token has already been
    resolved by other means.
    """

    source = "static"

    def __init__(self, token: Optional[str]) -> None:
        self._token = token

    def get_token(self) -> Optional[str]:
        return self._token or None


class CallableTokenProvider(BaseTokenProvider):
    """Delegates to a user-supplied callable.

    The escape hatch for sources this library does not model — a secrets
    manager, a refresh-capable client, a framework-specific context lookup.
    """

    source = "callable"

    def __init__(self, fn: Callable[[], Optional[str]], *, source: Optional[str] = None) -> None:
        """
        Args:
            fn: Zero-argument callable returning a token or ``None``.
            source: Optional label overriding ``"callable"``.
        """
        if not callable(fn):
            raise TypeError("fn must be callable")
        self._fn = fn
        if source:
            self.source = source

    def get_token(self) -> Optional[str]:
        return self._fn() or None


class EnvTokenProvider(BaseTokenProvider):
    """Reads a bare token out of an environment variable."""

    source = "env"

    def __init__(self, var: str = TOKEN_ENV) -> None:
        """
        Args:
            var: Environment variable holding the token value itself (not a
                path — see :class:`FileTokenProvider` for that).
        """
        self.var = var

    def get_token(self) -> Optional[str]:
        value = os.environ.get(self.var)
        return value.strip() if value and value.strip() else None


class FileTokenProvider(BaseTokenProvider):
    """Reads a token from a FABRIC token file.

    Accepts every shape FABRIC tooling writes:

    * a JSON object — the first key present from *keys* is used
      (``{"id_token": "eyJ..."}``, as written by ``fabric-cli tokens create``);
    * a JSON string — the token itself;
    * a bare compact JWS on a single line, with no JSON wrapper.

    The file is re-read only when its size or modification time changes, so
    hot-path callers can resolve a token per request without per-request I/O,
    while an externally refreshed token is still picked up.
    """

    source = "file"

    def __init__(
        self,
        path: Optional[Union[str, "os.PathLike[str]"]] = None,
        *,
        env_var: Optional[str] = TOKEN_LOCATION_ENV,
        keys: Sequence[str] = DEFAULT_TOKEN_KEYS,
        cache: bool = True,
        strict: bool = True,
    ) -> None:
        """
        Args:
            path: Explicit token file path.  Takes precedence over *env_var*.
            env_var: Environment variable consulted when *path* is ``None``.
                Pass ``None`` to require an explicit path.
            keys: JSON object keys searched, in order, for the token value.
            cache: Re-read only when the file's mtime or size changes.
            strict: Raise :class:`TokenSourceError` when the path is
                unconfigured or the file is unreadable.  When false, such
                failures yield ``None`` — the right choice inside a
                :class:`ChainTokenProvider`.
        """
        self._path = os.fspath(path) if path is not None else None
        self.env_var = env_var
        self.keys = tuple(keys)
        self.cache = cache
        self.strict = strict
        self._lock = threading.Lock()
        self._cached: Optional[Tuple[Tuple[int, int], str]] = None

    @property
    def path(self) -> Optional[str]:
        """The resolved token file path, or ``None`` if unconfigured."""
        if self._path:
            return self._path
        if self.env_var:
            value = os.environ.get(self.env_var)
            if value:
                return os.path.expanduser(value)
        return None

    def refresh(self) -> None:
        """Drop the cached token, forcing a re-read on the next call."""
        with self._lock:
            self._cached = None

    def get_token(self) -> Optional[str]:
        path = self.path
        if not path:
            if self.strict:
                raise TokenSourceError(
                    f"{self.env_var} environment variable is not set"
                    if self.env_var
                    else "No token file path was configured"
                )
            return None

        try:
            with self._lock:
                stat = os.stat(path)
                stamp = (stat.st_mtime_ns, stat.st_size)
                if self.cache and self._cached is not None and self._cached[0] == stamp:
                    return self._cached[1]
                with open(path, "r", encoding="utf-8") as fh:
                    content = fh.read()
                token = self._parse(content, path)
                if self.cache:
                    self._cached = (stamp, token)
                return token
        except TokenSourceError:
            if self.strict:
                raise
            log.debug("Token file %s unusable", path, exc_info=True)
            return None
        except OSError as e:
            if self.strict:
                raise TokenSourceError(f"Failed to read token from {path}: {e}") from e
            log.debug("Token file %s unreadable", path, exc_info=True)
            return None

    def _parse(self, content: str, path: str) -> str:
        """Extract the token from raw file *content*."""
        text = content.strip()
        if not text:
            raise TokenSourceError(f"Failed to read token from {path}: file is empty")

        try:
            data: Any = json.loads(text)
        except json.JSONDecodeError as e:
            # Tolerate a token file holding just the compact JWS.
            if _looks_like_jwt(text):
                return text
            raise TokenSourceError(f"Failed to read token from {path}: {e}") from e

        if isinstance(data, str):
            token = data.strip()
            if token:
                return token
        elif isinstance(data, dict):
            for key in self.keys:
                value = data.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()

        raise TokenSourceError(
            f"Unexpected token format in {path}: expected a JSON string or an object "
            f"with one of {list(self.keys)}"
        )

    def __repr__(self) -> str:
        return f"FileTokenProvider(path={self.path!r}, strict={self.strict})"


class HeaderTokenProvider(BaseTokenProvider):
    """Extracts a bearer token from HTTP headers.

    Args:
        headers: A header mapping, or a zero-argument callable returning one.
            Pass a callable for per-request resolution — see
            :mod:`fabric_mcp_common.integrations.fastmcp`.
        header_name: Header to read.
        scheme: Expected authentication scheme.
    """

    source = "bearer"

    def __init__(
        self,
        headers: HeadersLike,
        *,
        header_name: str = AUTHORIZATION_HEADER,
        scheme: str = BEARER_SCHEME,
    ) -> None:
        self._headers = headers
        self.header_name = header_name
        self.scheme = scheme

    def _resolve_headers(self) -> Optional[Mapping[str, str]]:
        if callable(self._headers):
            return self._headers()
        return self._headers

    def get_token(self) -> Optional[str]:
        return extract_bearer_token(
            self._resolve_headers(),
            header_name=self.header_name,
            scheme=self.scheme,
        )


class ChainTokenProvider(BaseTokenProvider):
    """Tries each provider in order and returns the first token found.

    Args:
        providers: Providers to consult, highest precedence first.
        skip_source_errors: Treat a provider's :class:`TokenSourceError` as
            "no token here" and continue.  When false, the error propagates.
    """

    source = "chain"

    def __init__(
        self,
        *providers: TokenProvider,
        skip_source_errors: bool = True,
    ) -> None:
        flat: list = []
        for p in providers:
            if p is None:
                continue
            if isinstance(p, ChainTokenProvider):
                flat.extend(p.providers)
            else:
                flat.append(p)
        self.providers: Tuple[TokenProvider, ...] = tuple(flat)
        self.skip_source_errors = skip_source_errors
        #: Label of the provider that satisfied the most recent successful call.
        self.last_source: Optional[str] = None

    def get_token(self) -> Optional[str]:
        for provider in self.providers:
            try:
                token = provider.get_token()
            except TokenSourceError:
                if not self.skip_source_errors:
                    raise
                log.debug("Token source %r unavailable, trying next", provider, exc_info=True)
                continue
            if token:
                self.last_source = getattr(provider, "source", None)
                return token
        self.last_source = None
        return None

    def __repr__(self) -> str:
        return f"ChainTokenProvider({', '.join(repr(p) for p in self.providers)})"


def _looks_like_jwt(text: str) -> bool:
    """Heuristic: a single-line, 3-segment, non-empty dotted string."""
    if any(ch.isspace() for ch in text):
        return False
    parts = text.split(".")
    return len(parts) == 3 and all(parts)


def read_token_from_file(
    path: Optional[Union[str, "os.PathLike[str]"]] = None,
    *,
    env_var: str = TOKEN_LOCATION_ENV,
    keys: Iterable[str] = DEFAULT_TOKEN_KEYS,
) -> str:
    """Read a FABRIC token from a token file.

    Convenience wrapper around :class:`FileTokenProvider` for one-shot reads;
    the compatibility entry point for the original
    ``fabric_api_mcp.auth.token.read_token_from_file``.

    Args:
        path: Explicit path.  Defaults to ``$FABRIC_TOKEN_LOCATION``.
        env_var: Environment variable consulted when *path* is omitted.
        keys: JSON keys searched for the token value.

    Returns:
        The token string.

    Raises:
        TokenSourceError: If the path is unset or the file cannot be read or
            parsed.  Subclasses ``ValueError``, matching the original contract.
    """
    return FileTokenProvider(
        path, env_var=env_var, keys=tuple(keys), cache=False, strict=True
    ).require_token()


__all__ = [
    "DEFAULT_TOKEN_KEYS",
    "TOKEN_ENV",
    "TOKEN_LOCATION_ENV",
    "BaseTokenProvider",
    "CallableTokenProvider",
    "ChainTokenProvider",
    "EnvTokenProvider",
    "FileTokenProvider",
    "HeaderTokenProvider",
    "HeadersLike",
    "StaticTokenProvider",
    "TokenProvider",
    "read_token_from_file",
]
