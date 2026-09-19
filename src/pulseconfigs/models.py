from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pulseconfigs.strategy import normalize_network, strategy_class, strategy_weight


PROTOCOLS = (
    "vless",
    "vmess",
    "trojan",
    "shadowsocks",
    "socks",
    "hysteria2",
    "tuic",
    "wireguard",
    "anytls",
)

SCHEME_TO_PROTOCOL = {
    "vless": "vless",
    "vmess": "vmess",
    "trojan": "trojan",
    "ss": "shadowsocks",
    "socks": "socks",
    "socks5": "socks",
    "hysteria2": "hysteria2",
    "hy2": "hysteria2",
    "tuic": "tuic",
    "wg": "wireguard",
    "wireguard": "wireguard",
    "anytls": "anytls",
}


@dataclass(slots=True)
class ProxyConfig:
    """Normalized share-link config."""

    raw: str
    protocol: str
    host: str
    port: int
    remark: str = ""
    security: str = ""
    network: str = ""
    flow: str = ""
    pbk: str = ""
    sid: str = ""
    sni: str = ""
    fingerprint: str = ""
    allow_insecure: bool = False
    source_id: str = ""
    params: dict[str, str] = field(default_factory=dict)

    # Health fields filled by prove stages
    l2_ok: bool = False
    l3_passes: int = 0
    l3_rounds: int = 0
    delays_ms: list[float] = field(default_factory=list)
    median_delay_ms: float | None = None
    reject_reason: str = ""
    # Delay was measured (vs pass/fail-only without latency)
    delay_measured: bool = False
    # Stability (filled from state window)
    stability_score: float = 0.5
    # Iran L4 probe (optional)
    iran_ok: bool | None = None
    iran_delay_ms: float | None = None
    iran_probed_at: str = ""

    @property
    def is_reality(self) -> bool:
        return self.security.lower() == "reality" or bool(self.pbk)

    @property
    def is_vision(self) -> bool:
        f = self.flow.lower()
        return "vision" in f or f == "xtls-rprx-vision"

    @property
    def strategy(self) -> str:
        return strategy_class(self)

    @property
    def strategy_weight(self) -> float:
        return strategy_weight(self)

    @property
    def has_forward_secrecy(self) -> bool:
        sec = self.security.lower()
        if sec in {"tls", "reality"}:
            return True
        if self.protocol in {"hysteria2", "tuic", "anytls", "wireguard"}:
            return True
        if normalize_network(self.network) == "quic":
            return True
        return False

    @property
    def verified(self) -> bool:
        return self.l3_rounds > 0 and self.l3_passes == self.l3_rounds

    def fingerprint_key(self) -> str:
        """CDN-aware endpoint uniqueness key (host:port:proto + identity crumbs)."""
        identity = self.params.get("id") or self.params.get("uuid") or self.params.get("password") or ""
        net = normalize_network(self.network)
        return f"{self.protocol}|{self.host.lower()}|{self.port}|{identity}|{self.security}|{net}|{self.flow}|{self.pbk}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol,
            "host": self.host,
            "port": self.port,
            "security": self.security,
            "network": normalize_network(self.network),
            "flow": self.flow,
            "strategy": self.strategy,
            "median_delay_ms": self.median_delay_ms,
            "l3_passes": self.l3_passes,
            "l3_rounds": self.l3_rounds,
            "iran_ok": self.iran_ok,
        }
