"""
Configuration, read once from the environment.

Rename this package and the env-var prefix; the shape is what matters. Note
which defaults *flip with local mode* — rate limiting and metrics are off for a
single-user stdio process and on for a served one.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Literal, Tuple

#: Values treated as false. Anything else is true, so "off" and "no" are *true* —
#: a sharp edge worth knowing before you copy this.
FALSEY = ("0", "false", "False", "")


def _flag(name: str, default: str) -> bool:
    return os.environ.get(name, default) not in FALSEY


@dataclass
class ServerConfig:
    local_mode: bool
    transport: str
    host: str
    port: int

    log_level: str
    log_format: Literal["text", "json"]

    metrics_enabled: bool
    metrics_client_ip_labels: bool

    rate_limit: str
    rate_limit_enabled: bool
    rate_limit_trusted_proxies: Tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def from_env(cls) -> "ServerConfig":
        local = _flag("MY_MCP_LOCAL_MODE", "0")
        return cls(
            local_mode=local,
            transport=os.environ.get("MY_MCP_TRANSPORT", "stdio" if local else "http"),
            host=os.environ.get("HOST", "0.0.0.0"),
            port=int(os.environ.get("PORT", "5000")),
            log_level=os.environ.get("LOG_LEVEL", "INFO").upper(),
            log_format=os.environ.get("LOG_FORMAT", "text").lower(),
            # Off in local mode: a stdio process serves one user.
            metrics_enabled=_flag("METRICS_ENABLED", "0" if local else "1"),
            # Off by default, matching the library: one Prometheus series per
            # source address is unbounded on a public endpoint. Turn it on only
            # if the endpoint is not publicly reachable, or you have the budget.
            metrics_client_ip_labels=_flag("METRICS_CLIENT_IP_LABELS", "0"),
            rate_limit=os.environ.get("RATE_LIMIT", "60/minute"),
            rate_limit_enabled=_flag("RATE_LIMIT_ENABLED", "0" if local else "1"),
            # Peers allowed to assert the real client address via X-Real-IP.
            #
            # Empty by default — trust nobody. Anything broader is a guess about
            # your network, and a wrong guess is a rate-limit bypass: any host
            # inside a trusted range can set X-Real-IP and rotate it for a fresh
            # bucket per request. List ONLY your reverse proxy, ideally as a /32.
            #
            # A whole private range (10.0.0.0/8, 172.16.0.0/12) is not a safe
            # value: it covers every other container, VPN client and LAN host
            # that can reach this port.
            rate_limit_trusted_proxies=tuple(
                entry.strip()
                for entry in os.environ.get("RATE_LIMIT_TRUSTED_PROXIES", "").split(",")
                if entry.strip()
            ),
        )


config = ServerConfig.from_env()
