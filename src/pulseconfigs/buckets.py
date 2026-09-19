from __future__ import annotations

from dataclasses import dataclass, field

from pulseconfigs.models import ProxyConfig
from pulseconfigs.strategy import (
    CDN_LIKE,
    IMPERSONATION,
    QUIC_LIKE,
    host_slash24,
    strategy_class,
)

FAST_MS = 800.0

W_STABILITY = 0.35
W_STRATEGY = 0.25
W_LATENCY = 0.20
W_SECURE = 0.10


@dataclass
class Buckets:
    all: list[ProxyConfig] = field(default_factory=list)
    verified: list[ProxyConfig] = field(default_factory=list)
    fast: list[ProxyConfig] = field(default_factory=list)
    secure: list[ProxyConfig] = field(default_factory=list)
    top100: list[ProxyConfig] = field(default_factory=list)
    top5: list[ProxyConfig] = field(default_factory=list)
    top5_speed: list[ProxyConfig] = field(default_factory=list)
    top5_iran: list[ProxyConfig] = field(default_factory=list)
    by_protocol: dict[str, list[ProxyConfig]] = field(default_factory=dict)
    reality: list[ProxyConfig] = field(default_factory=list)
    vision: list[ProxyConfig] = field(default_factory=list)
    broken: list[ProxyConfig] = field(default_factory=list)
    iran_meta: dict[str, object] = field(default_factory=dict)


def _delay_key(cfg: ProxyConfig) -> float:
    return cfg.median_delay_ms if cfg.median_delay_ms is not None else 1e9


def _latency_norm(cfg: ProxyConfig) -> float:
    if cfg.median_delay_ms is None or not cfg.delay_measured:
        return 0.4
    return max(0.0, min(1.0, 1.0 - (cfg.median_delay_ms / 2000.0)))


def censorship_score(cfg: ProxyConfig) -> float:
    stability = max(0.0, min(1.0, cfg.stability_score))
    strategy = max(0.0, min(1.0, cfg.strategy_weight))
    latency = _latency_norm(cfg)
    secure = 1.0 if (cfg.has_forward_secrecy and not cfg.allow_insecure) else 0.0
    score = (
        W_STABILITY * stability
        + W_STRATEGY * strategy
        + W_LATENCY * latency
        + W_SECURE * secure
    )
    if cfg.iran_ok is True:
        score += 0.35
        if cfg.iran_delay_ms is not None:
            score += max(0.0, 0.1 * (1.0 - min(cfg.iran_delay_ms, 3000.0) / 3000.0))
    elif cfg.iran_ok is False:
        score -= 0.5
    return score


def select_top_speed(verified: list[ProxyConfig], n: int = 5) -> list[ProxyConfig]:
    return sorted(verified, key=_delay_key)[:n]


def select_censorship_pack(verified: list[ProxyConfig], n: int = 5) -> list[ProxyConfig]:
    """Constraint-aware Free pack: strategy diversity + /24 cap + secure preference."""
    if not verified:
        return []

    ranked = sorted(verified, key=censorship_score, reverse=True)
    selected: list[ProxyConfig] = []
    used_slash24: set[str] = set()
    quic_count = 0

    def try_add(cfg: ProxyConfig) -> bool:
        nonlocal quic_count
        if cfg in selected or len(selected) >= n:
            return False
        s24 = host_slash24(cfg.host)
        if s24 in used_slash24:
            return False
        strat = strategy_class(cfg)
        if strat in QUIC_LIKE and quic_count >= 1:
            return False
        selected.append(cfg)
        used_slash24.add(s24)
        if strat in QUIC_LIKE:
            quic_count += 1
        return True

    # Pass 1: greedy by score
    for cfg in ranked:
        try_add(cfg)
        if len(selected) >= n:
            break

    def imp_count() -> int:
        return sum(1 for c in selected if strategy_class(c) in IMPERSONATION)

    def has_cdn() -> bool:
        return any(strategy_class(c) in CDN_LIKE for c in selected)

    def swap_in(predicate) -> bool:
        nonlocal quic_count
        for cfg in ranked:
            if cfg in selected or not predicate(cfg):
                continue
            s24 = host_slash24(cfg.host)
            if s24 in used_slash24:
                continue
            strat = strategy_class(cfg)
            if strat in QUIC_LIKE and quic_count >= 1:
                continue
            # Prefer swapping the lowest-scored selected that is not unique CDN/imp filler
            victims = sorted(selected, key=censorship_score)
            for victim in victims:
                vstrat = strategy_class(victim)
                if vstrat in CDN_LIKE and sum(1 for c in selected if strategy_class(c) in CDN_LIKE) <= 1:
                    if strategy_class(cfg) not in CDN_LIKE:
                        continue
                if vstrat in IMPERSONATION and imp_count() <= 2:
                    if strategy_class(cfg) not in IMPERSONATION:
                        continue
                selected.remove(victim)
                used_slash24.discard(host_slash24(victim.host))
                if vstrat in QUIC_LIKE:
                    quic_count = max(0, quic_count - 1)
                selected.append(cfg)
                used_slash24.add(s24)
                if strat in QUIC_LIKE:
                    quic_count += 1
                return True
            if len(selected) < n:
                return try_add(cfg)
        return False

    if not has_cdn():
        swap_in(lambda c: strategy_class(c) in CDN_LIKE)
    while imp_count() < 2:
        if not swap_in(lambda c: strategy_class(c) in IMPERSONATION):
            break

    for cfg in ranked:
        if len(selected) >= n:
            break
        try_add(cfg)

    selected.sort(key=lambda c: (0 if c.iran_ok else 1, -censorship_score(c)))
    return selected[:n]


def build_buckets(
    pool: list[ProxyConfig],
    rejected: list[ProxyConfig] | None = None,
    *,
    iran_meta: dict[str, object] | None = None,
) -> Buckets:
    meta = dict(iran_meta or {})
    b = Buckets(all=list(pool), broken=list(rejected or []), iran_meta=meta)
    verified = [c for c in pool if c.verified]
    by_delay = sorted(verified, key=_delay_key)
    b.verified = by_delay
    b.fast = [c for c in verified if c.median_delay_ms is not None and c.median_delay_ms < FAST_MS]
    b.secure = [c for c in verified if c.has_forward_secrecy and not c.allow_insecure]
    b.top100 = by_delay[:100]
    b.top5_speed = select_top_speed(verified, 5)
    b.top5 = select_censorship_pack(verified, 5)

    iran_ok = [c for c in verified if c.iran_ok is True]
    if iran_ok:
        b.top5_iran = select_censorship_pack(iran_ok, 5)
        if len(b.top5_iran) < 5:
            pad = [c for c in b.top5 if c not in b.top5_iran]
            b.top5_iran = (b.top5_iran + pad)[:5]
    else:
        b.top5_iran = list(b.top5)

    if meta.get("probe_online"):
        b.top5 = list(b.top5_iran)

    by_proto: dict[str, list[ProxyConfig]] = {}
    for c in pool:
        by_proto.setdefault(c.protocol, []).append(c)
        if c.is_reality:
            b.reality.append(c)
        if c.is_vision:
            b.vision.append(c)
    b.by_protocol = by_proto
    return b
