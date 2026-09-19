from __future__ import annotations

from typing import Protocol

# Anti-DPI strategy classes used for censorship-aware ranking.
STRATEGY_REALITY_VISION = "reality_vision"
STRATEGY_REALITY_TCP = "reality_tcp"
STRATEGY_REALITY_XHTTP = "reality_xhttp"
STRATEGY_CDN_TLS = "cdn_tls"
STRATEGY_TLS_VISION = "tls_vision"
STRATEGY_QUIC_SPEED = "quic_speed"
STRATEGY_ANYTLS = "anytls"
STRATEGY_LEGACY = "legacy"

IMPERSONATION = frozenset(
    {
        STRATEGY_REALITY_VISION,
        STRATEGY_REALITY_TCP,
        STRATEGY_REALITY_XHTTP,
        STRATEGY_TLS_VISION,
        STRATEGY_ANYTLS,
    }
)
CDN_LIKE = frozenset({STRATEGY_CDN_TLS, STRATEGY_REALITY_XHTTP})
QUIC_LIKE = frozenset({STRATEGY_QUIC_SPEED})

# Relative anti-DPI weights for Iran/China-oriented packs (higher = prefer).
STRATEGY_WEIGHT: dict[str, float] = {
    STRATEGY_REALITY_VISION: 1.0,
    STRATEGY_REALITY_XHTTP: 0.95,
    STRATEGY_REALITY_TCP: 0.9,
    STRATEGY_CDN_TLS: 0.85,
    STRATEGY_TLS_VISION: 0.8,
    STRATEGY_ANYTLS: 0.8,
    STRATEGY_QUIC_SPEED: 0.45,
    STRATEGY_LEGACY: 0.25,
}

_CDN_TRANSPORTS = frozenset({"ws", "websocket", "grpc", "gun", "httpupgrade", "h2", "http", "xhttp", "splithttp"})
_XHTTP = frozenset({"xhttp", "splithttp"})
_TCP_LIKE = frozenset({"", "tcp", "raw"})


class StrategyAware(Protocol):
    protocol: str
    security: str
    network: str
    flow: str
    pbk: str

    @property
    def is_reality(self) -> bool: ...

    @property
    def is_vision(self) -> bool: ...


def normalize_network(network: str) -> str:
    n = (network or "tcp").lower().strip()
    if n in {"splithttp", "split"}:
        return "xhttp"
    if n in {"websocket"}:
        return "ws"
    if n == "gun":
        return "grpc"
    return n


def strategy_class(cfg: StrategyAware) -> str:
    """Classify a config into an anti-DPI strategy bucket."""
    net = normalize_network(cfg.network)
    sec = (cfg.security or "").lower()
    if cfg.protocol in {"hysteria2", "tuic"} or net == "quic":
        return STRATEGY_QUIC_SPEED
    if cfg.protocol == "anytls":
        return STRATEGY_ANYTLS
    if cfg.is_reality and cfg.is_vision:
        return STRATEGY_REALITY_VISION
    if cfg.is_reality and net in _XHTTP:
        return STRATEGY_REALITY_XHTTP
    if cfg.is_reality:
        return STRATEGY_REALITY_TCP
    if cfg.is_vision and sec == "tls":
        return STRATEGY_TLS_VISION
    if sec == "tls" and net in _CDN_TRANSPORTS:
        return STRATEGY_CDN_TLS
    if sec == "tls" and net in _TCP_LIKE:
        return STRATEGY_TLS_VISION if cfg.is_vision else STRATEGY_LEGACY
    return STRATEGY_LEGACY


def strategy_weight(cfg: StrategyAware) -> float:
    return STRATEGY_WEIGHT.get(strategy_class(cfg), 0.2)


def is_impersonation(cfg: StrategyAware) -> bool:
    return strategy_class(cfg) in IMPERSONATION


def is_cdn_like(cfg: StrategyAware) -> bool:
    return strategy_class(cfg) in CDN_LIKE


def host_slash24(host: str) -> str:
    """Return IPv4 /24 key, or host itself for hostnames / non-v4."""
    h = host.strip().lower().strip("[]")
    parts = h.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return h
