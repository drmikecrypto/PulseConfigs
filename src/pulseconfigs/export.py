from __future__ import annotations

import base64
import json
from pathlib import Path

import yaml

from pulseconfigs.buckets import Buckets
from pulseconfigs.models import PROTOCOLS, ProxyConfig
from pulseconfigs.strategy import strategy_class


def write_text(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def write_base64_sub(path: Path, lines: list[str]) -> None:
    plain = "\n".join(lines) + ("\n" if lines else "")
    encoded = base64.b64encode(plain.encode("utf-8")).decode("ascii")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(encoded + "\n", encoding="utf-8")


def configs_to_lines(configs: list[ProxyConfig]) -> list[str]:
    return [c.raw for c in configs]


def _clash_proxy(cfg: ProxyConfig) -> dict | None:
    name = (cfg.remark or f"{cfg.protocol}-{cfg.host}")[:64]
    if cfg.protocol == "vless":
        p: dict = {
            "name": name,
            "type": "vless",
            "server": cfg.host,
            "port": cfg.port,
            "uuid": cfg.params.get("uuid") or cfg.params.get("id") or "",
            "network": cfg.network or "tcp",
            "tls": cfg.security in {"tls", "reality"},
            "udp": True,
            "flow": cfg.flow or "",
            "client-fingerprint": cfg.fingerprint or "chrome",
        }
        if cfg.security == "reality" or cfg.pbk:
            p["tls"] = True
            p["reality-opts"] = {
                "public-key": cfg.pbk,
                "short-id": cfg.sid or "",
            }
            p["servername"] = cfg.sni or ""
        elif cfg.sni:
            p["servername"] = cfg.sni
        if cfg.allow_insecure:
            p["skip-cert-verify"] = True
        net = (cfg.network or "tcp").lower()
        if net in {"ws", "websocket"}:
            p["network"] = "ws"
            p["ws-opts"] = {
                "path": cfg.params.get("path") or "/",
                "headers": {"Host": cfg.params.get("host") or cfg.sni or ""},
            }
        elif net in {"grpc", "gun"}:
            p["network"] = "grpc"
            p["grpc-opts"] = {
                "grpc-service-name": cfg.params.get("serviceName") or cfg.params.get("servicename") or "",
            }
        elif net == "httpupgrade":
            p["network"] = "ws"  # Clash Meta often maps httpupgrade via ws-opts
            p["ws-opts"] = {
                "path": cfg.params.get("path") or "/",
                "headers": {"Host": cfg.params.get("host") or cfg.sni or ""},
                "v2ray-http-upgrade": True,
            }
        return p
    if cfg.protocol == "vmess":
        return {
            "name": name,
            "type": "vmess",
            "server": cfg.host,
            "port": cfg.port,
            "uuid": cfg.params.get("id") or "",
            "alterId": int(cfg.params.get("aid") or 0),
            "cipher": cfg.params.get("scy") or "auto",
            "network": cfg.network or "tcp",
            "tls": bool(cfg.security),
            "udp": True,
            "servername": cfg.sni or "",
            "skip-cert-verify": cfg.allow_insecure,
        }
    if cfg.protocol == "trojan":
        return {
            "name": name,
            "type": "trojan",
            "server": cfg.host,
            "port": cfg.port,
            "password": cfg.params.get("password") or cfg.params.get("id") or "",
            "network": cfg.network or "tcp",
            "sni": cfg.sni or "",
            "udp": True,
            "skip-cert-verify": cfg.allow_insecure,
        }
    if cfg.protocol == "shadowsocks":
        return {
            "name": name,
            "type": "ss",
            "server": cfg.host,
            "port": cfg.port,
            "cipher": cfg.params.get("method") or "aes-128-gcm",
            "password": cfg.params.get("password") or "",
            "udp": True,
        }
    if cfg.protocol == "socks":
        return {
            "name": name,
            "type": "socks5",
            "server": cfg.host,
            "port": cfg.port,
            "udp": True,
        }
    if cfg.protocol == "hysteria2":
        return {
            "name": name,
            "type": "hysteria2",
            "server": cfg.host,
            "port": cfg.port,
            "password": cfg.params.get("password") or cfg.params.get("id") or "",
            "sni": cfg.sni or "",
            "skip-cert-verify": cfg.allow_insecure,
        }
    if cfg.protocol == "tuic":
        uid = cfg.params.get("uuid") or (cfg.params.get("id") or "").split(":")[0]
        password = cfg.params.get("password") or ""
        if ":" in (cfg.params.get("id") or "") and not password:
            password = cfg.params["id"].split(":", 1)[1]
        return {
            "name": name,
            "type": "tuic",
            "server": cfg.host,
            "port": cfg.port,
            "uuid": uid,
            "password": password,
            "congestion-controller": cfg.params.get("congestion_control") or "bbr",
            "udp-relay-mode": cfg.params.get("udp_relay_mode") or "native",
            "sni": cfg.sni or "",
            "skip-cert-verify": cfg.allow_insecure,
        }
    if cfg.protocol == "anytls":
        return {
            "name": name,
            "type": "anytls",
            "server": cfg.host,
            "port": cfg.port,
            "password": cfg.params.get("password") or cfg.params.get("id") or "",
            "sni": cfg.sni or "",
            "skip-cert-verify": cfg.allow_insecure,
        }
    # WireGuard Clash mapping is fragile across versions — skip rather than emit invalid YAML
    return None


def export_clash(configs: list[ProxyConfig]) -> str:
    proxies = []
    names = []
    for cfg in configs:
        p = _clash_proxy(cfg)
        if not p:
            continue
        # ensure unique names
        base = p["name"]
        n = base
        i = 1
        while n in names:
            i += 1
            n = f"{base}-{i}"
        p["name"] = n
        names.append(n)
        proxies.append(p)
    doc = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "proxies": proxies,
        "proxy-groups": [
            {"name": "PROXY", "type": "select", "proxies": names or ["DIRECT"]},
        ],
        "rules": ["MATCH,PROXY"],
    }
    return yaml.safe_dump(doc, allow_unicode=True, sort_keys=False)


def _singbox_outbound(cfg: ProxyConfig) -> dict | None:
    tag = (cfg.remark or f"{cfg.protocol}-{cfg.host}")[:64]
    if cfg.protocol == "vless":
        outbound: dict = {
            "type": "vless",
            "tag": tag,
            "server": cfg.host,
            "server_port": cfg.port,
            "uuid": cfg.params.get("uuid") or cfg.params.get("id") or "",
            "packet_encoding": "xudp",
        }
        if cfg.flow:
            outbound["flow"] = cfg.flow
        tls: dict = {}
        if cfg.security in {"tls", "reality"} or cfg.pbk:
            tls = {
                "enabled": True,
                "server_name": cfg.sni or cfg.host,
                "insecure": cfg.allow_insecure,
                "utls": {"enabled": True, "fingerprint": cfg.fingerprint or "chrome"},
            }
            if cfg.pbk or cfg.security == "reality":
                tls["reality"] = {"enabled": True, "public_key": cfg.pbk, "short_id": cfg.sid or ""}
            outbound["tls"] = tls
        transport = _singbox_transport(cfg)
        if transport:
            outbound["transport"] = transport
        return outbound
    if cfg.protocol == "trojan":
        outbound = {
            "type": "trojan",
            "tag": tag,
            "server": cfg.host,
            "server_port": cfg.port,
            "password": cfg.params.get("password") or cfg.params.get("id") or "",
            "tls": {
                "enabled": True,
                "server_name": cfg.sni or cfg.host,
                "insecure": cfg.allow_insecure,
            },
        }
        return outbound
    if cfg.protocol == "shadowsocks":
        return {
            "type": "shadowsocks",
            "tag": tag,
            "server": cfg.host,
            "server_port": cfg.port,
            "method": cfg.params.get("method") or "aes-128-gcm",
            "password": cfg.params.get("password") or "",
        }
    if cfg.protocol == "hysteria2":
        return {
            "type": "hysteria2",
            "tag": tag,
            "server": cfg.host,
            "server_port": cfg.port,
            "password": cfg.params.get("password") or cfg.params.get("id") or "",
            "tls": {
                "enabled": True,
                "server_name": cfg.sni or cfg.host,
                "insecure": cfg.allow_insecure,
            },
        }
    if cfg.protocol == "tuic":
        uid = cfg.params.get("uuid") or (cfg.params.get("id") or "").split(":")[0]
        password = cfg.params.get("password") or ""
        return {
            "type": "tuic",
            "tag": tag,
            "server": cfg.host,
            "server_port": cfg.port,
            "uuid": uid,
            "password": password,
            "congestion_control": cfg.params.get("congestion_control") or "bbr",
            "tls": {
                "enabled": True,
                "server_name": cfg.sni or cfg.host,
                "insecure": cfg.allow_insecure,
            },
        }
    if cfg.protocol == "anytls":
        return {
            "type": "anytls",
            "tag": tag,
            "server": cfg.host,
            "server_port": cfg.port,
            "password": cfg.params.get("password") or cfg.params.get("id") or "",
            "tls": {
                "enabled": True,
                "server_name": cfg.sni or cfg.host,
                "insecure": cfg.allow_insecure,
            },
        }
    if cfg.protocol == "vmess":
        outbound = {
            "type": "vmess",
            "tag": tag,
            "server": cfg.host,
            "server_port": cfg.port,
            "uuid": cfg.params.get("id") or "",
            "security": cfg.params.get("scy") or "auto",
            "alter_id": int(cfg.params.get("aid") or 0),
        }
        if cfg.security:
            outbound["tls"] = {
                "enabled": True,
                "server_name": cfg.sni or cfg.host,
                "insecure": cfg.allow_insecure,
                "utls": {"enabled": True, "fingerprint": cfg.fingerprint or "chrome"},
            }
        transport = _singbox_transport(cfg)
        if transport:
            outbound["transport"] = transport
        return outbound
    if cfg.protocol == "socks":
        user = cfg.params.get("username") or cfg.params.get("user") or ""
        password = cfg.params.get("password") or ""
        outbound = {
            "type": "socks",
            "tag": tag,
            "server": cfg.host,
            "server_port": cfg.port,
            "version": "5",
        }
        if user:
            outbound["username"] = user
            outbound["password"] = password
        return outbound
    if cfg.protocol == "wireguard":
        private = cfg.params.get("id") or cfg.params.get("privatekey") or cfg.params.get("private_key") or ""
        # userinfo in URI is the private key
        local_addr = cfg.params.get("address") or "10.0.0.2/32"
        addresses = [a.strip() for a in str(local_addr).split(",") if a.strip()]
        return {
            "type": "wireguard",
            "tag": tag,
            "server": cfg.host,
            "server_port": cfg.port,
            "local_address": addresses or ["10.0.0.2/32"],
            "private_key": private,
            "peer_public_key": cfg.params.get("publickey") or cfg.params.get("public_key") or "",
            "mtu": int(cfg.params.get("mtu") or 1400),
        }
    return None


def _singbox_transport(cfg: ProxyConfig) -> dict | None:
    from pulseconfigs.strategy import normalize_network

    net = normalize_network(cfg.network)
    if net in {"ws"}:
        return {
            "type": "ws",
            "path": cfg.params.get("path") or "/",
            "headers": {"Host": cfg.params.get("host") or cfg.sni or ""},
        }
    if net in {"grpc"}:
        return {
            "type": "grpc",
            "service_name": cfg.params.get("serviceName") or cfg.params.get("servicename") or "",
        }
    if net in {"httpupgrade"}:
        return {
            "type": "httpupgrade",
            "path": cfg.params.get("path") or "/",
            "host": cfg.params.get("host") or cfg.sni or "",
        }
    if net in {"xhttp"}:
        return {
            "type": "http",
            "path": cfg.params.get("path") or "/",
            "host": cfg.params.get("host") or cfg.sni or "",
            "headers": {"Host": cfg.params.get("host") or cfg.sni or ""},
        }
    return None


def export_singbox(configs: list[ProxyConfig]) -> str:
    outbounds: list[dict] = [
        {"type": "direct", "tag": "direct"},
        {"type": "block", "tag": "block"},
    ]
    tags: list[str] = []
    for cfg in configs:
        ob = _singbox_outbound(cfg)
        if not ob:
            continue
        tag = ob["tag"]
        base = tag
        i = 1
        while tag in tags:
            i += 1
            tag = f"{base}-{i}"
            ob["tag"] = tag
        tags.append(tag)
        outbounds.append(ob)
    outbounds.append(
        {
            "type": "selector",
            "tag": "proxy",
            "outbounds": tags or ["direct"],
        }
    )
    doc = {
        "log": {"level": "info"},
        "outbounds": outbounds,
    }
    return json.dumps(doc, ensure_ascii=False, indent=2)


def export_tier_dir(root: Path, name: str, configs: list[ProxyConfig]) -> dict[str, str]:
    """Write configs.txt / configs_base64.txt / clash.yaml / singbox.json. Skip if empty."""
    rel: dict[str, str] = {}
    if not configs:
        return rel
    d = root / name
    lines = configs_to_lines(configs)
    write_text(d / "configs.txt", lines)
    write_base64_sub(d / "configs_base64.txt", lines)
    (d / "clash.yaml").write_text(export_clash(configs), encoding="utf-8")
    (d / "singbox.json").write_text(export_singbox(configs), encoding="utf-8")
    for fname in ("configs.txt", "configs_base64.txt", "clash.yaml", "singbox.json"):
        rel[fname] = f"{name}/{fname}"
    return rel


def export_all(root: Path, buckets: Buckets) -> dict[str, object]:
    """Write all publish artifacts under root. Returns relative path map."""
    root.mkdir(parents=True, exist_ok=True)
    files: dict[str, object] = {}

    for tier_name, configs in (
        ("all", buckets.all),
        ("verified", buckets.verified),
        ("fast", buckets.fast),
        ("secure", buckets.secure),
    ):
        files[tier_name] = export_tier_dir(root, tier_name, configs)

    if buckets.top100:
        write_text(root / "top100.txt", configs_to_lines(buckets.top100))
        files["top100"] = "top100.txt"
    if buckets.top5:
        write_text(root / "top5.txt", configs_to_lines(buckets.top5))
        files["top5"] = "top5.txt"
    if buckets.top5_speed:
        write_text(root / "top5_speed.txt", configs_to_lines(buckets.top5_speed))
        files["top5_speed"] = "top5_speed.txt"
    if buckets.top5_iran:
        write_text(root / "top5_iran.txt", configs_to_lines(buckets.top5_iran))
        files["top5_iran"] = "top5_iran.txt"

    # Shortlist for Iran L4 phone probes (US-verified, strategy-diverse, capped)
    shortlist = _build_shortlist(buckets.verified, limit=60)
    if shortlist:
        write_text(root / "candidates.txt", configs_to_lines(shortlist))
        write_json_candidates(root / "candidates.json", shortlist)
        files["candidates"] = "candidates.txt"
        files["candidates_json"] = "candidates.json"

    proto_files: dict[str, str] = {}
    for proto in PROTOCOLS:
        cfgs = buckets.by_protocol.get(proto) or []
        if not cfgs:
            continue
        lines = configs_to_lines(cfgs)
        write_text(root / "protocols" / f"{proto}.txt", lines)
        write_base64_sub(root / "protocols" / f"{proto}_base64.txt", lines)
        proto_files[proto] = f"protocols/{proto}.txt"
        proto_files[f"{proto}_base64"] = f"protocols/{proto}_base64.txt"
    files["protocols"] = proto_files

    feat: dict[str, str] = {}
    if buckets.reality:
        write_text(root / "features" / "reality.txt", configs_to_lines(buckets.reality))
        write_base64_sub(root / "features" / "reality_base64.txt", configs_to_lines(buckets.reality))
        feat["reality"] = "features/reality.txt"
    if buckets.vision:
        write_text(root / "features" / "vision.txt", configs_to_lines(buckets.vision))
        write_base64_sub(root / "features" / "vision_base64.txt", configs_to_lines(buckets.vision))
        feat["vision"] = "features/vision.txt"
    files["features"] = feat

    if buckets.broken:
        write_text(root / "archive" / "broken.txt", [f"{c.reject_reason}\t{c.raw}" for c in buckets.broken[:5000]])
        files["broken"] = "archive/broken.txt"

    return files


def _build_shortlist(verified: list[ProxyConfig], limit: int = 60) -> list[ProxyConfig]:
    """Diverse US-verified shortlist for Iran phone L4 probing."""
    from pulseconfigs.buckets import censorship_score
    from pulseconfigs.strategy import host_slash24

    ranked = sorted(verified, key=censorship_score, reverse=True)
    out: list[ProxyConfig] = []
    used_s24: set[str] = set()
    used_strat: dict[str, int] = {}
    for cfg in ranked:
        if len(out) >= limit:
            break
        s24 = host_slash24(cfg.host)
        if s24 in used_s24:
            continue
        strat = strategy_class(cfg)
        if used_strat.get(strat, 0) >= max(3, limit // 8):
            continue
        out.append(cfg)
        used_s24.add(s24)
        used_strat[strat] = used_strat.get(strat, 0) + 1
    return out


def write_json_candidates(path: Path, configs: list[ProxyConfig]) -> None:
    rows = [
        {
            "fingerprint": c.fingerprint_key(),
            "raw": c.raw,
            "protocol": c.protocol,
            "strategy": strategy_class(c),
            "host": c.host,
            "port": c.port,
            "median_delay_ms": c.median_delay_ms,
        }
        for c in configs
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"candidates": rows}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
