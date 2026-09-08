from __future__ import annotations

from pulseconfigs.models import ProxyConfig
from pulseconfigs.normalize import dedupe, structural_ok


def filter_l0_l1(configs: list[ProxyConfig]) -> tuple[list[ProxyConfig], list[ProxyConfig]]:
    """Return (accepted, rejected) after structural checks + dedupe."""
    accepted: list[ProxyConfig] = []
    rejected: list[ProxyConfig] = []
    for cfg in configs:
        ok, reason = structural_ok(cfg)
        if not ok:
            cfg.reject_reason = reason
            rejected.append(cfg)
            continue
        accepted.append(cfg)
    return dedupe(accepted), rejected
