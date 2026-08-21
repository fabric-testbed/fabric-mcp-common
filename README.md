# fabric-mcp-common

Shared plumbing for FABRIC MCP servers: **token authentication**, **Prometheus
instrumentation**, and **structured logging**.

Extracted from [`fabric_api_mcp`](https://github.com/fabric-testbed/fabric_api_mcp) so that
new MCP implementations get this for free instead of reimplementing bearer extraction, JWT
claim decoding, local-vs-server token resolution, metric definitions, and identity plumbing
for logs and dashboards.

The point isn't only code reuse. Because every adopting server reports the **same metric
names and log fields**, one Grafana dashboard works against all of them — and that dashboard
ships in this package.

- **No third-party dependencies** in the core (`auth` + `logging`): pure standard library.
- **Everything heavier is an extra** — Prometheus, JWKS verification, FastMCP.
- **Framework adapters** for FastMCP and Starlette/ASGI, imported on demand.
- **Never logs a token.** Every `__repr__`, log-field helper and parameter sanitiser is
  redacted by construction.

| Subpackage | Contents | Needs |
| :-- | :-- | :-- |
| `fabric_mcp_common.auth` | bearer extraction, JWT claims, token sources, JWKS verification | stdlib (`[verify]` for signatures) |
| `fabric_mcp_common.metrics` | the `mcp_*` metric contract, ASGI middleware, bundled dashboard | `[metrics]` |
| `fabric_mcp_common.logging` | JSON formatter, level wiring, tool-logging decorator | stdlib |
| `fabric_mcp_common.integrations` | FastMCP and Starlette adapters | `[fastmcp]` for FastMCP |

---

## Starting a new server

[`examples/minimal-server/`](examples/minimal-server/) is a runnable skeleton: auth,
structured logging, Prometheus metrics, rate limiting, a Dockerfile, an installer that
sources the shared shell library, and tests — with the security defaults already set
correctly.

```bash
cp -r examples/minimal-server ../my-new-mcp && cd ../my-new-mcp
python3 -m venv .venv && .venv/bin/pip install -e '.[test]'
.venv/bin/python -m pytest
MY_MCP_LOCAL_MODE=1 .venv/bin/python -m my_mcp
```

Its README documents the handful of things worth not re-deriving — chiefly why a
rate-limit key may only come from unforgeable inputs, and why `X-Forwarded-For` is
never one of them. This library's own test suite resolves every symbol the example
imports, so an API change here fails *this* repo rather than someone else's build.

---

## Install

```bash
pip install fabric_mcp_common                    # auth + logging (no dependencies)
pip install "fabric_mcp_common[metrics]"         # + Prometheus instrumentation
pip install "fabric_mcp_common[fastmcp]"         # + FastMCP request-context adapter
pip install "fabric_mcp_common[verify]"          # + CredMgr JWKS signature verification
pip install "fabric_mcp_common[all]"             # everything
```

---

## Quick start

### 1. Authenticate an MCP tool call

One resolver, shared by every tool, working in both deployment modes: local/stdio (token
read from `$FABRIC_TOKEN_LOCATION`) and server/HTTP (token read from the request's
`Authorization: Bearer` header).

```python
from fabric_mcp_common.integrations.fastmcp import build_resolver

RESOLVER = build_resolver(local_mode=config.local_mode)

def fabric_query_slices(...):
    auth = RESOLVER.resolve()               # raises MissingTokenError if unauthenticated
    log.info("query_slices by %s", auth.identity)
    fm = FabricManagerV2(id_token=auth.token, ...)
    ...
```

`resolve()` returns an [`AuthContext`](#authcontext): the raw token to forward upstream,
the decoded claims, and which source supplied it.

### 2. Identity for logging, metrics and rate limits

Middleware needs the caller's identity but must never fail on a bad token. These helpers
never raise, and memoize the decode on `request.state` so several middlewares in one stack
decode the JWT once rather than once each.

```python
from fabric_mcp_common.integrations.starlette import (
    auth_failure_reason, client_ip, identity_fields, rate_limit_key,
)

class AccessLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        fields = identity_fields(request)    # user_sub, user_email, user_uuid, project_uuid, client_ip
        response = await call_next(request)
        log.info("HTTP %s %s -> %s", request.method, request.url.path,
                 response.status_code, extra=fields)
        return response

# Verified JWT sub, else the address your proxy asserts, else the socket peer.
# See "Rate-limit keys" below — trusted_proxies should name only the proxy.
limiter = Limiter(
    key_func=lambda r: rate_limit_key(r, trusted_proxies=("172.31.240.10/32",))
)

reason = auth_failure_reason(request)        # None | malformed_header | missing_token
if reason:                                   #      | invalid_jwt | expired_token
    mcp_auth_failures_total.labels(reason=reason, client_ip=client_ip(request)).inc()
```

A tool-logging decorator sees headers rather than a request object; the FastMCP adapter
covers that with one header fetch and one decode:

```python
from fabric_mcp_common.integrations.fastmcp import current_trace_context

trace = current_trace_context()
# {"request_id", "user_sub", "user_email", "user_uuid",
#  "project_name", "project_uuid", "client_ip"}
```

### 3. Claims without any framework

```python
from fabric_mcp_common.auth import TokenClaims

claims = TokenClaims.from_token(token)
claims.email          # "user@example.org"
claims.project_name   # first project's name
claims.is_expired()   # False when there is no exp claim — absence is not expiry
claims.identity()     # email → name → sub → uuid → "anonymous"
claims.get("sub")     # also a Mapping, so dict-style access still works
```

### 4. Verify signatures (opt-in)

Only needed when your server *terminates* authentication. When tokens are forwarded to a
FABRIC API that validates them itself — the usual MCP proxy case — the unverified decode
above is sufficient and avoids a hard dependency on CredMgr availability.

```python
from fabric_mcp_common.integrations.fastmcp import build_resolver
from fabric_mcp_common.auth.verify import CredMgrVerifier

RESOLVER = build_resolver(
    local_mode=False,
    verifier=CredMgrVerifier(credmgr_host="cm.fabric-testbed.net"),
)

auth = RESOLVER.resolve()   # signature + expiry checked
assert auth.verified
```

This wraps `fss_utils.jwt_validate.JWTValidator` — the same validator
`fabrictestbed.util.utils.Utils.decode_token` uses, hitting
`https://<credmgr_host>/credmgr/certs` — so key fetching, caching and algorithm selection
stay consistent with the rest of the FABRIC stack. On top of it this adds thread safety,
typed errors, and `TokenClaims` output.

---

### 5. Instrument the server, and get the dashboard for free

```python
from fabric_mcp_common.metrics import (
    MetricsMiddleware, SecurityMetricsMiddleware, configure, dashboard_path,
)

configure(client_ip_labels=False)      # see Cardinality below
app.add_middleware(MetricsMiddleware)
app.add_middleware(SecurityMetricsMiddleware)
```

That populates the whole `mcp_*` contract — 11 metrics covering HTTP volume and latency,
tool calls, rate-limit hits, auth outcomes, and per-user counters. The bundled dashboard
(22 panels) queries exactly those names, so it works against your server unedited:

```python
dashboard_path()   # .../fabric_mcp_common/dashboards/mcp-server.json
```

Point Grafana's provisioning at that path, or copy it in. `metrics.METRIC_NAMES` is the
authoritative list, and a test asserts every name the dashboard queries exists in it — so
the dashboard cannot silently drift from the code.

Record tool calls yourself if you are not using the decorator below:

```python
from fabric_mcp_common.metrics import record_tool_call

record_tool_call(tool="my_tool", duration_seconds=0.42, status="ok",
                 user_uuid=..., user_email=..., project_name=...)
```

#### Cardinality

Prometheus keeps one series per label combination for the process lifetime, so two labels
need care:

- **`client_ip` is off by default.** A scanner sweeping a public endpoint would otherwise
  mint a series per source address, permanently. When disabled the label still exists (the
  dashboard's queries keep working) with the constant value `disabled`. Opt in with
  `configure(client_ip_labels=True)` only if the endpoint isn't publicly reachable or you
  have the series budget.
- **`path` is normalised** through `normalize_path()`, which collapses UUIDs, long hex
  strings and integers to `{id}` — so `/slices/2f1c…/nodes/7` becomes `/slices/{id}/nodes/{id}`
  instead of one series per slice.

### 6. Logging

```python
from fabric_mcp_common.logging import configure_logging, make_tool_logger

configure_logging(level="INFO", fmt="json", app_loggers=("myserver",))
```

One stderr handler (stdout stays clean for stdio transports), your loggers at the chosen
level, noisy libraries pinned to WARNING, root held at WARNING. This package's own
namespace is always registered, so library diagnostics honour your level instead of being
clamped — see [Logging namespace](#logging-namespace).

`make_tool_logger` is a factory: bind the logger name and metrics policy once, then use the
plain decorator at every tool.

```python
tool_logger = make_tool_logger(
    logger="myserver.tools",
    metrics_enabled=lambda: config.metrics_enabled,   # callable = read at call time
)

@tool_logger("my_tool")
async def my_tool(...): ...
```

Per call it logs sanitised parameters (DEBUG), start and completion with duration and
result size (INFO), and errors with a traceback (ERROR) — attaching caller identity to
every line as structured `extra` fields, and recording the tool metrics. Parameters whose
names look credential-bearing (`token`, `id_token`, `password`, `*_key`, `secret`, …) are
replaced with `***REDACTED***`, and long strings truncated.

#### Logging namespace

Everything logs under `fabric.common.*`. Configuring that **single parent** captures all of
it, including subpackages added later:

```python
logging.getLogger("fabric.common").setLevel(logging.DEBUG)
```

`configure_logging()` does this for you. Miss it and the library's debug output is
unreachable — the root logger is deliberately held at WARNING.

### 7. Rate-limit keys

A rate-limit key **is** the bucket, so anything a caller controls can be rotated for a
fresh bucket per request — bypassing the limit outright rather than merely skewing it. But
the key also has to distinguish callers: behind a proxy, keying on the socket peer puts
everyone in one bucket and turns your limit into a service-wide cap.

`rate_limit_key` therefore derives the key from unforgeable inputs only:

1. the token's claim, **only from signature-verified claims** (`require_verified=True`);
2. `X-Real-IP`, **only when the socket peer is in `trusted_proxies`**;
3. the socket peer.

```python
from fabric_mcp_common.integrations.starlette import rate_limit_key, trusted_client_ip

rate_limit_key(request, trusted_proxies=("172.31.240.10/32",))
trusted_client_ip(request, trusted_proxies=("172.31.240.10/32",))
```

**`trusted_proxies` should name only the proxy.** A whole private range (`10.0.0.0/8`,
`172.16.0.0/12`) covers every other container, VPN client and LAN host that can reach the
port — any of which could then assert an arbitrary `X-Real-IP`. Pin the proxy to a fixed
address and list that `/32`. Left empty, keying falls back to the socket peer: safe, but a
shared bucket if a proxy fronts you, so log a warning at startup when it is unset.

**`X-Forwarded-For` is never used for a key**, even from a trusted peer. nginx sets it with
`$proxy_add_x_forwarded_for`, which *appends* to whatever the client sent, so the left-most
entry stays caller-controlled. `X-Real-IP` comes from `$remote_addr`, which overwrites. Use
`client_ip` (which does consult `X-Forwarded-For`) for logs and metric labels only, where a
spoofed value is misleading rather than a control bypass.

Verified claims come from a verifier — see [Verify signatures](#4-verify-signatures-opt-in).
Without one, `request_claims` performs an unverified decode, `verified` is always False, and
keying is per address. `require_verified=False` restores the old behaviour if something
upstream has already authenticated the token and you accept caller-chosen keys.

#### Migrating from 0.2.x

`rate_limit_key` changed behaviour in 0.3.0. Previously it used the claim from an
*unverified* decode and fell back to the left-most `X-Forwarded-For` entry — a caller could
set either.

| If you were relying on | Do this |
|---|---|
| per-user keys without a verifier | configure a verifier, or pass `require_verified=False` and accept the risk |
| per-client keys behind a proxy | pass `trusted_proxies=("<proxy>/32",)` |
| `client_ip` for logs/metrics | no change — that function is unchanged |

### 8. Installer boilerplate

Every FABRIC MCP server's `install.sh` needs the same opening moves: coloured logging,
OS and package-manager detection, idempotent package installation, finding a new enough
Python, creating a venv. That lives here as a shell library instead of being copied per
server.

```bash
FMC_RAW="https://raw.githubusercontent.com/fabric-testbed/fabric-mcp-common/main"
curl -fsSL "$FMC_RAW/fabric_mcp_common/templates/install-common.sh" -o /tmp/install-common.sh
source /tmp/install-common.sh

detect_os                 # sets OS, PKG_MGR
ensure_command git        # install if absent, no-op if present
ensure_python             # sets PYTHON to a 3.11+ interpreter, installing if needed
ensure_venv "$VENV_DIR"   # create if absent, then upgrade pip inside it
```

Bootstrap installers run **before** any virtualenv exists, so they cannot import this
package to locate the file — fetch it over HTTPS as above. Anything running *after*
installation can skip the network:

```python
from fabric_mcp_common.templates import install_script_path, install_script_url

install_script_path()   # packaged path, resolves from an installed wheel
install_script_url()    # canonical raw URL, for cold-start installers
```

Tunables, set before sourcing: `FMC_PYTHON_MIN_MINOR` (default `11`) and
`FMC_PYTHON_CANDIDATES`. Callers are expected to sanity-check that the functions they
rely on are defined after sourcing, so a version skew fails immediately with a clear
message rather than as `command not found` mid-install.


---

## API

### Token sources

Every provider answers one question — *what is the caller's token right now?* — and hides
where it came from. All resolve lazily on each call, so rotated files and late environment
changes are picked up without a restart.

| Provider | Source |
| :-- | :-- |
| `StaticTokenProvider(token)` | A token you already have. |
| `EnvTokenProvider(var="FABRIC_ID_TOKEN")` | A bare token in an environment variable. |
| `FileTokenProvider(path=None, env_var="FABRIC_TOKEN_LOCATION")` | A FABRIC token file. |
| `HeaderTokenProvider(headers)` | An `Authorization` header; `headers` may be a callable. |
| `CallableTokenProvider(fn)` | Anything else — a secrets manager, a refreshing client. |
| `ChainTokenProvider(*providers)` | First provider to yield a token wins. |

`FileTokenProvider` accepts every shape FABRIC tooling writes — a `{"id_token": "..."}`
object (as written by `fabric-cli tokens create`), a bare JSON string, or an unwrapped
compact JWS — and re-reads only when the file's mtime or size changes.

### `TokenResolver`

```python
TokenResolver(provider, *, verifier=None, verify=None, enforce_expiry=False, leeway=0.0)
```

| Method | Behaviour |
| :-- | :-- |
| `token()` | The raw token, or `None`. |
| `require_token()` | The raw token; raises `MissingTokenError`. |
| `claims()` | `TokenClaims`, empty when unauthenticated. **Never raises** — for logs and metrics. |
| `resolve()` | An `AuthContext`; raises on missing/invalid/expired. |
| `try_resolve()` | An `AuthContext` or `None`, never raising — for paths that tolerate anonymous callers. |
| `with_provider(p)` | A copy bound to a different source, same policy. |

`enforce_expiry` is **off by default**, matching the FABRIC convention that upstream
services are the authority on token validity. Turn it on to fail fast at the edge.

### `AuthContext`

`token`, `claims`, `source` (`"bearer"`, `"file"`, `"env"`, …), plus `identity`,
`user_id`, `user_uuid`, `email`, `project_uuid`, `project_name`, `verified`,
`authorization_header()` and `log_fields()`.

### Errors

All derive from `AuthError`, which derives from **`ValueError`** — so existing
`except ValueError` handlers in FABRIC MCP call sites keep working, while new code can
catch the precise type. Each carries `error_type` and `to_dict()` matching the FABRIC MCP
JSON error contract, `{"error": ..., "details": ...}`.

| Error | `error_type` | Raised when |
| :-- | :-- | :-- |
| `MissingTokenError` | `unauthorized` | No source supplied a token. |
| `InvalidTokenError` | `unauthorized` | Token is malformed or fails verification. |
| `ExpiredTokenError` | `unauthorized` | Token parsed but expired (subclass of `InvalidTokenError`). |
| `TokenSourceError` | `unauthorized` | A configured source is unreadable or misconfigured. |
| `VerificationUnavailableError` | `server_error` | JWKS unreachable or the `verify` extra is missing — a server fault, not a bad credential. |

---

## Migrating from `fabric_api_mcp.auth.token`

| Before | After |
| :-- | :-- |
| `extract_bearer_token(headers)` | `extract_bearer_token(headers)` — unchanged |
| `decode_token_claims(token)` | `decode_token_claims(token)` — unchanged, or `TokenClaims.from_token(token)` |
| `read_token_from_file()` | `read_token_from_file()` — unchanged, or `FileTokenProvider()` |
| `validate_token_presence(token)` | `TokenResolver.require_token()` |
| `get_http_headers(...)` + `extract_bearer_token` + `raise ValueError` | `RESOLVER.resolve()` |
| hand-rolled `_get_client_ip(request)` | `integrations.starlette.client_ip(request)` |
| `decode_token_claims` + manual `exp` re-decode | `integrations.starlette.auth_failure_reason(request)` |
| header fetch + decode + IP parsing in a tool decorator | `integrations.fastmcp.current_trace_context()` |
| `fabric_api_mcp.metrics` definitions | `fabric_mcp_common.metrics` |
| `middleware/metrics.py`, `middleware/security_metrics.py` | `metrics.MetricsMiddleware`, `metrics.SecurityMetricsMiddleware` |
| `log_helper/formatters.JsonFormatter` | `logging.JsonFormatter` |
| `log_helper/config.configure_logging()` | `logging.configure_logging(level=..., fmt=..., app_loggers=...)` |
| `log_helper/decorators.tool_logger` | `logging.make_tool_logger(logger=..., metrics_enabled=...)` |

Behaviour changes to be aware of:

1. **`extract_bearer_token` returns `None`, not `""`,** for a header of exactly `"Bearer "`.
   Callers that tested falsiness are unaffected.
2. **`read_token_from_file` raises `TokenSourceError`** rather than plain `ValueError` —
   but it *is* a `ValueError`, with the same message text.

3. **`client_ip` metric labels are off by default** (see
   [Cardinality](#cardinality)). An existing deployment whose dashboards chart per-IP
   series must call `configure(client_ip_labels=True)` to keep them.
4. **`path` metric labels are normalised.** No effect on static routes; a route carrying an
   id now reports `{id}` instead of one series per value.
5. **JSON logs now include `user_uuid`, `project_name` and `project_uuid`.** The previous
   formatter's field list omitted them, so they were silently dropped in JSON mode.

Everything else is byte-compatible, including the
`"Authentication Required: Missing or invalid Authorization Bearer token."` message, the
metric names and label sets, and the `mcp_auth_failures_total` reason values.

---

## Design notes

**Unverified decode is the default, and that is deliberate.** `TokenClaims.from_token`
base64-decodes the payload without checking the signature. For logging, metrics labels,
rate-limit keys and display that is exactly right, and it cannot fail. `claims.verified`
is `False` for such claims and only ever `True` after `CredMgrVerifier` succeeds, so no
code path can mistake one for the other.

**Server mode never falls back to a local token file.** `build_provider(local_mode=False)`
returns *only* the request-header provider. A server must not serve someone else's request
with the operator's own credential.

**Missing `exp` is not expiry.** `is_expired()` returns `False` when there is no `exp`
claim, rather than treating absence as failure.

**The ASGI identity helpers import no Starlette.** They duck-type the request object
(`.headers`, `.url.path`, `.client`, `.state`), so they work with Starlette, FastAPI and
anything compatible without adding a dependency. (The metrics *middleware* does subclass
`BaseHTTPMiddleware`, which is why `[metrics]` pulls Starlette in.)

**One JWT decode per request, shared across the stack.** `request_claims()` memoises on
`request.state`, so an access-log, metrics and security-metrics middleware in the same stack
decode once rather than three times.

**The metric contract is the reusable artifact, not the dashboard.** A dashboard is only
portable because the names and labels underneath it are fixed; `METRIC_NAMES` is declared
explicitly rather than derived from `prometheus_client` internals, and a test ties the
shipped JSON to it.

---

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[test,all]"
pytest --cov=fabric_mcp_common --cov-report=term-missing
```

The suite stubs out `fastmcp` and `fss_utils`, so it runs with no FABRIC packages
installed.

## License

MIT — see [LICENSE](LICENSE).
