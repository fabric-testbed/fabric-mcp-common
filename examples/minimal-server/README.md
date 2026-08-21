# Minimal FABRIC MCP server

A runnable skeleton for a new MCP server built on `fabric_mcp_common`. Copy this
directory, rename `my_mcp`, delete the example tools, and you have auth, structured
logging, Prometheus metrics, rate limiting, a container image and an installer
already wired — with the security defaults set correctly from the first commit.

```bash
cp -r examples/minimal-server ../my-new-mcp && cd ../my-new-mcp
python3 -m venv .venv && .venv/bin/pip install -e '.[test]'
.venv/bin/python -m pytest                 # 10 tests
MY_MCP_LOCAL_MODE=1 .venv/bin/python -m my_mcp
```

## What's here

| File | Purpose |
| :-- | :-- |
| `my_mcp/config.py` | Env → dataclass. Note the defaults that flip with local mode. |
| `my_mcp/observability.py` | `configure_logging()` and the bound `@tool_logger`. |
| `my_mcp/auth.py` | The shared token resolver: `require_token` / `optional_token`. |
| `my_mcp/rate_limit.py` | The rate-limit key. **Read this before changing it.** |
| `my_mcp/tools/example.py` | Two tools — one unauthenticated, one requiring a token. |
| `my_mcp/__main__.py` | FastMCP wiring, stdio and HTTP transports, `/metrics`. |
| `Dockerfile` | No `--prerelease=allow`; `fastmcp` capped below 4.0. |
| `docker-compose.yml` + `nginx.conf` | nginx in front, with the proxy pinned to one address. |
| `install.sh` | Sources the shared installer library instead of copying it. |
| `tests/test_smoke.py` | Imports, plus guards on the security defaults. |

## Renaming it

1. `git mv my_mcp your_pkg`, then replace `my_mcp` throughout (`pyproject.toml`,
   `Dockerfile`, `install.sh`, `tests/`, and the `app_loggers` in
   `observability.py`).
2. Change the `MY_MCP_` env prefix in `config.py`.
3. Change `FastMCP(name=...)` in `__main__.py`.
4. Replace `my_mcp/tools/example.py` with your tools, keeping the `TOOLS` dict.

## The five things worth not re-deriving

Each of these is the result of a real bug in `fabric_api_mcp`.

**1. Rate-limit keys must come from unforgeable inputs.** The key *is* the bucket,
so anything a caller controls can be rotated for a fresh bucket per request —
bypassing the limit entirely, not merely skewing it. Ordering: verified claim →
`X-Real-IP` from a *configured* proxy peer → socket peer.

**2. `X-Forwarded-For` must never decide a key.** nginx sets it from
`$proxy_add_x_forwarded_for`, which **appends** to the client's value, so its
left-most entry is caller-controlled even on a trusted hop. `X-Real-IP` comes from
`$remote_addr`, which overwrites. Use `client_ip()` for logs, `trusted_client_ip()`
for decisions.

**3. An unverified claim is attacker input.** `request_claims()` performs an
unverified payload decode, and a JWT payload can be written by hand with no signing
key. `require_verified=True` is the default — leave it on. Enabling per-user keying
means configuring a verifier, not flipping a flag.

**4. `RATE_LIMIT_TRUSTED_PROXIES` should name only your proxy.** A whole private
range (`10.0.0.0/8`, `172.16.0.0/12`) covers every other container, VPN client and
LAN host that can reach the port, any of which could then forge `X-Real-IP`. Empty
is safe but non-discriminating: behind a proxy every caller shares one bucket, which
caps the whole service. The skeleton warns at startup when it is unset — that is the
failure mode that otherwise looks like nothing.

**5. Pin dependencies in *both* manifests.** The Dockerfile installs from
`requirements.txt`; `pip install .` uses `pyproject.toml`. Pinning one leaves the
other open. And do not pass `--prerelease=allow` to a production build — that once
resolved `fastmcp` to a 4.0 beta, which pulled `mcp 2.x`, removed a module the app
imported, and produced an image that built green and died at import.

## Deploying

```bash
docker compose up -d
```

Keep `RATE_LIMIT_TRUSTED_PROXIES` and nginx's `ipv4_address` in step. If you change
the subnet, run `docker compose down` first — Docker will not re-IPAM an existing
network, and a static IP outside the old subnet stops the container from starting.

If you would rather not pin a static IP, set `RATE_LIMIT_TRUSTED_PROXIES` to the
compose network's own subnet instead. That trusts every container on it rather than
one address — broader, but they are all yours, and it needs no network surgery.

## Environment variables

| Variable | Default | Notes |
| :-- | :-- | :-- |
| `MY_MCP_LOCAL_MODE` | `0` | `1` for stdio/single-user. Flips the three defaults below. |
| `MY_MCP_TRANSPORT` | `stdio` (local) / `http` | |
| `HOST` / `PORT` | `0.0.0.0` / `5000` | |
| `LOG_LEVEL` / `LOG_FORMAT` | `INFO` / `text` | `json` for structured output. |
| `METRICS_ENABLED` | `0` (local) / `1` | Adds `/metrics`. |
| `METRICS_CLIENT_IP_LABELS` | `0` | On is one series per source address — unbounded on a public endpoint. |
| `RATE_LIMIT` | `60/minute` | |
| `RATE_LIMIT_ENABLED` | `0` (local) / `1` | |
| `RATE_LIMIT_TRUSTED_PROXIES` | *empty* | Comma-separated CIDRs. **Only your proxy.** |
| `FABRIC_TOKEN_LOCATION` | — | Token file, local mode only. |

Only `{"0", "false", "False", ""}` are false, so `off` and `no` are **true**.

## Grafana

`fabric_mcp_common` ships a dashboard matching the metric contract these
middlewares populate, so it works unedited:

```python
from fabric_mcp_common.metrics import dashboard_path
print(dashboard_path())
```

## Next steps this skeleton leaves out

- **CI.** A clean `pip install -r requirements.txt` plus an import check, on every
  PR and nightly, catches a dependency breaking before a deploy does.
- **Signature verification**, if your server terminates authentication rather than
  forwarding tokens upstream. See the library's "Verify signatures" section; it also
  enables per-user rate limiting.
