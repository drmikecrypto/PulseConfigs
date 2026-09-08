"""Optional GeoIP country splits — TLD/remark heuristics for now."""

from __future__ import annotations

from collections import defaultdict

from pulseconfigs.models import ProxyConfig


def group_by_country_heuristic(configs: list[ProxyConfig]) -> dict[str, list[ProxyConfig]]:
    """Rough grouping using remark country codes if present (e.g. 'DE |')."""
    groups: dict[str, list[ProxyConfig]] = defaultdict(list)
    for cfg in configs:
        cc = "ZZ"
        remark = cfg.remark or ""
        parts = remark.replace("🚩", " ").split()
        for p in parts:
            if len(p) == 2 and p.isalpha() and p.isupper():
                cc = p.upper()
                break
        groups[cc].append(cfg)
    return dict(groups)
