from __future__ import annotations

import hashlib
import ipaddress
import re
from urllib.parse import quote, urlencode, urlparse, urlunparse

from pulseconfigs.models import ProxyConfig

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def is_private_or_bogus_host(host: str) -> bool:
    h = host.strip().lower().strip("[]")
    if not h or h in {"localhost", "0.0.0.0", "::", "::1"}:
        return True
    try:
        ip = ipaddress.ip_address(h)
        return bool(
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except ValueError:
        # hostname — reject obvious locals
        return h.endswith(".local") or h.endswith(".localhost")


def structural_ok(cfg: ProxyConfig) -> tuple[bool, str]:
    if not cfg.host or not (1 <= cfg.port <= 65535):
        return False, "bad_endpoint"
    if is_private_or_bogus_host(cfg.host):
        return False, "private_or_bogus_host"
    if cfg.protocol in {"vless", "vmess", "tuic"}:
        uid = cfg.params.get("uuid") or cfg.params.get("id") or ""
        # tuic may be uuid:password
        uid_only = uid.split(":", 1)[0]
        if uid_only and not _UUID_RE.match(uid_only):
            # some providers use non-uuid ids for vmess — allow non-empty
            if cfg.protocol == "vmess" and len(uid_only) >= 8:
                pass
            elif cfg.protocol != "vmess":
                return False, "bad_uuid"
    if cfg.protocol == "shadowsocks" and cfg.params.get("plugin"):
        return False, "ss_plugin_unsupported"
    if cfg.security.lower() == "reality" and not cfg.pbk:
        return False, "reality_missing_pbk"
    if cfg.is_vision and cfg.network and cfg.network.lower() not in {"", "tcp", "raw"}:
        return False, "vision_requires_tcp"
    return True, ""


def dedupe(configs: list[ProxyConfig]) -> list[ProxyConfig]:
    """CDN-aware dedupe by fingerprint_key; keep first occurrence."""
    seen: set[str] = set()
    out: list[ProxyConfig] = []
    for cfg in configs:
        key = cfg.fingerprint_key()
        if key in seen:
            continue
        seen.add(key)
        out.append(cfg)
    return out


def brand_remark(cfg: ProxyConfig, brand: str = "PulseConfigs") -> str:
    digest = hashlib.sha256(cfg.fingerprint_key().encode()).hexdigest()[:6]
    proto = cfg.protocol.upper()
    tag = "REALITY" if cfg.is_reality else ("VISION" if cfg.is_vision else proto)
    return f"{tag} | @{brand} | {digest}"


def rebrand_raw(cfg: ProxyConfig, brand: str = "PulseConfigs") -> str:
    """Replace URI fragment with branded remark; leave body intact."""
    remark = brand_remark(cfg, brand)
    raw = cfg.raw
    if "#" in raw:
        raw = raw.rsplit("#", 1)[0]
    return f"{raw}#{quote(remark)}"


def apply_brand(configs: list[ProxyConfig], brand: str = "PulseConfigs") -> list[ProxyConfig]:
    for cfg in configs:
        cfg.remark = brand_remark(cfg, brand)
        cfg.raw = rebrand_raw(cfg, brand)
    return configs
