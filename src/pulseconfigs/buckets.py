from __future__ import annotations

from dataclasses import dataclass, field

from pulseconfigs.models import ProxyConfig


FAST_MS = 800.0


@dataclass
class Buckets:
    all: list[ProxyConfig] = field(default_factory=list)
    verified: list[ProxyConfig] = field(default_factory=list)
    fast: list[ProxyConfig] = field(default_factory=list)
    secure: list[ProxyConfig] = field(default_factory=list)
    top100: list[ProxyConfig] = field(default_factory=list)
    top5: list[ProxyConfig] = field(default_factory=list)
    by_protocol: dict[str, list[ProxyConfig]] = field(default_factory=dict)
    reality: list[ProxyConfig] = field(default_factory=list)
    vision: list[ProxyConfig] = field(default_factory=list)
    broken: list[ProxyConfig] = field(default_factory=list)


def _delay_key(cfg: ProxyConfig) -> float:
    return cfg.median_delay_ms if cfg.median_delay_ms is not None else 1e9


def build_buckets(pool: list[ProxyConfig], rejected: list[ProxyConfig] | None = None) -> Buckets:
    b = Buckets(all=list(pool), broken=list(rejected or []))
    verified = [c for c in pool if c.verified]
    verified.sort(key=_delay_key)
    b.verified = verified
    b.fast = [c for c in verified if c.median_delay_ms is not None and c.median_delay_ms < FAST_MS]
    b.secure = [
        c
        for c in verified
        if c.has_forward_secrecy and not c.allow_insecure
    ]
    b.top100 = verified[:100]
    b.top5 = verified[:5]
    by_proto: dict[str, list[ProxyConfig]] = {}
    for c in pool:
        by_proto.setdefault(c.protocol, []).append(c)
        if c.is_reality:
            b.reality.append(c)
        if c.is_vision:
            b.vision.append(c)
    b.by_protocol = by_proto
    return b
