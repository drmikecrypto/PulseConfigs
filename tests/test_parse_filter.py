from __future__ import annotations

import base64
import json

from pulseconfigs.buckets import build_buckets, censorship_score, select_censorship_pack, select_top_speed
from pulseconfigs.export import export_clash, export_singbox
from pulseconfigs.filter import filter_l0_l1
from pulseconfigs.iran_rank import apply_iran_probes, merge_probe_reports
from pulseconfigs.models import ProxyConfig
from pulseconfigs.normalize import structural_ok
from pulseconfigs.parse import parse_share_link, parse_subscription_text
from pulseconfigs.prove import UNMEASURED_DELAY_MS, _collect_results
from pulseconfigs.stability import apply_stability
from pulseconfigs.strategy import (
    STRATEGY_CDN_TLS,
    STRATEGY_QUIC_SPEED,
    STRATEGY_REALITY_VISION,
    STRATEGY_REALITY_XHTTP,
    normalize_network,
    strategy_class,
)
from pathlib import Path


def test_parse_vless_reality_vision():
    uri = (
        "vless://11111111-1111-1111-1111-111111111111@example.com:443"
        "?encryption=none&flow=xtls-rprx-vision&security=reality"
        "&sni=www.cloudflare.com&fp=chrome&pbk=abcdefghijklmnopqrstuvwx&sid=abcd1234"
        "&type=tcp#reality-vision"
    )
    cfg = parse_share_link(uri)
    assert cfg is not None
    assert cfg.protocol == "vless"
    assert cfg.is_reality
    assert cfg.is_vision
    assert cfg.pbk
    assert strategy_class(cfg) == STRATEGY_REALITY_VISION
    ok, reason = structural_ok(cfg)
    assert ok, reason


def test_parse_xhttp_reality():
    uri = (
        "vless://11111111-1111-1111-1111-111111111111@example.com:443"
        "?encryption=none&security=reality&type=xhttp&mode=stream-one"
        "&pbk=abcdefghijklmnopqrstuvwx&sid=abcd&sni=www.yahoo.com&fp=chrome#xhttp"
    )
    cfg = parse_share_link(uri)
    assert cfg is not None
    assert normalize_network(cfg.network) == "xhttp"
    assert strategy_class(cfg) == STRATEGY_REALITY_XHTTP
    ok, reason = structural_ok(cfg)
    assert ok, reason


def test_reject_reality_ws():
    uri = (
        "vless://11111111-1111-1111-1111-111111111111@example.com:443"
        "?encryption=none&security=reality&type=ws&pbk=abcdefghijklmnopqrstuvwx#bad"
    )
    cfg = parse_share_link(uri)
    assert cfg is not None
    ok, reason = structural_ok(cfg)
    assert not ok
    assert reason == "reality_unsupported_transport"


def test_reject_reality_without_pbk():
    uri = (
        "vless://11111111-1111-1111-1111-111111111111@example.com:443"
        "?encryption=none&security=reality&type=tcp#bad"
    )
    cfg = parse_share_link(uri)
    assert cfg is not None
    ok, reason = structural_ok(cfg)
    assert not ok
    assert reason == "reality_missing_pbk"


def test_reject_ss_plugin():
    uri = "ss://YWVzLTEyOC1nY206cGFzcw@1.2.3.4:8388?plugin=obfs-local%3Bobfs%3Dhttp#ss"
    cfg = parse_share_link(uri)
    assert cfg is not None
    ok, reason = structural_ok(cfg)
    assert not ok
    assert reason == "ss_plugin_unsupported"


def test_parse_vmess_json():
    payload = {
        "v": "2",
        "ps": "test",
        "add": "1.2.3.4",
        "port": "10086",
        "id": "11111111-1111-1111-1111-111111111111",
        "aid": 0,
        "net": "ws",
        "type": "none",
        "host": "example.com",
        "path": "/ray",
        "tls": "tls",
    }
    b64 = base64.b64encode(json.dumps(payload).encode()).decode()
    cfg = parse_share_link(f"vmess://{b64}")
    assert cfg is not None
    assert cfg.protocol == "vmess"
    assert cfg.host == "1.2.3.4"
    assert cfg.port == 10086
    assert cfg.network == "ws"
    assert strategy_class(cfg) == STRATEGY_CDN_TLS


def test_parse_trojan_hy2_tuic_wg_anytls_socks():
    samples = [
        "trojan://password@host.example:443?security=tls&sni=host.example&type=tcp#t",
        "hy2://secret@host.example:443?sni=host.example#h",
        "tuic://11111111-1111-1111-1111-111111111111:pass@host.example:443?congestion_control=bbr#tu",
        "wireguard://PRIVATEKEY@host.example:51820?publickey=PUB&address=10.0.0.2/32#wg",
        "anytls://password@host.example:443?sni=host.example#a",
        "socks5://user:pass@1.2.3.4:1080#s",
    ]
    for uri in samples:
        cfg = parse_share_link(uri)
        assert cfg is not None, uri
        ok, reason = structural_ok(cfg)
        assert ok, f"{uri} -> {reason}"
    hy2 = parse_share_link(samples[1])
    assert strategy_class(hy2) == STRATEGY_QUIC_SPEED


def test_private_host_rejected():
    cfg = parse_share_link("vless://11111111-1111-1111-1111-111111111111@127.0.0.1:443?encryption=none#x")
    assert cfg is not None
    ok, reason = structural_ok(cfg)
    assert not ok
    assert reason == "private_or_bogus_host"


def test_subscription_base64_and_filter():
    links = "\n".join(
        [
            "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443?encryption=none&security=tls&type=tcp#a",
            "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443?encryption=none&security=reality&type=tcp#bad-reality",
            "ss://YWVzLTEyOC1nY206cGFzcw@5.6.7.8:8388?plugin=obfs-local#bad-ss",
        ]
    )
    body = base64.b64encode(links.encode()).decode()
    parsed = parse_subscription_text(body)
    assert len(parsed) >= 3
    ok, bad = filter_l0_l1(parsed)
    assert len(ok) == 1
    assert any(c.reject_reason == "reality_missing_pbk" for c in bad)
    assert any(c.reject_reason == "ss_plugin_unsupported" for c in bad)


def _verified(host: str, delay: float, **kwargs: object) -> ProxyConfig:
    c = ProxyConfig(
        raw=f"vless://11111111-1111-1111-1111-111111111111@{host}:443?encryption=none&security=tls&type=tcp#n",
        protocol="vless",
        host=host,
        port=443,
        security="tls",
        network="tcp",
        l3_rounds=3,
        l3_passes=3,
        median_delay_ms=delay,
        delays_ms=[delay],
        delay_measured=True,
        stability_score=0.8,
    )
    for k, v in kwargs.items():
        setattr(c, k, v)
    return c


def test_buckets_top5_speed_and_censorship():
    configs = []
    for i in range(10):
        configs.append(_verified(f"1.2.{i}.10", float(100 + i)))
    configs.append(
        ProxyConfig(
            raw="vless://11111111-1111-1111-1111-111111111111@9.9.9.9:443?encryption=none#x",
            protocol="vless",
            host="9.9.9.9",
            port=443,
            l3_rounds=3,
            l3_passes=1,
            median_delay_ms=50,
            delay_measured=True,
        )
    )
    b = build_buckets(configs)
    assert len(b.verified) == 10
    assert len(b.top5_speed) == 5
    assert b.top5_speed[0].median_delay_ms == 100
    assert len(b.top5) == 5


def test_censorship_pack_limits_quic_and_slash24():
    pool = [
        _verified(
            "10.0.0.1",
            50,
            security="reality",
            pbk="abcdefghijklmnopqrstuvwx",
            flow="xtls-rprx-vision",
            network="tcp",
        ),
        _verified(
            "10.0.0.2",  # same /24
            40,
            security="reality",
            pbk="abcdefghijklmnopqrstuvwx",
            network="tcp",
        ),
        _verified(
            "cdn.example.com",
            80,
            security="tls",
            network="ws",
            params={"path": "/ws", "host": "cdn.example.com"},
        ),
        ProxyConfig(
            raw="hy2://secret@udp.example.com:443?sni=udp.example.com#h1",
            protocol="hysteria2",
            host="udp.example.com",
            port=443,
            security="tls",
            l3_rounds=3,
            l3_passes=3,
            median_delay_ms=30,
            delay_measured=True,
            stability_score=0.9,
        ),
        ProxyConfig(
            raw="hy2://secret@udp2.example.com:443?sni=udp2.example.com#h2",
            protocol="hysteria2",
            host="udp2.example.com",
            port=443,
            security="tls",
            l3_rounds=3,
            l3_passes=3,
            median_delay_ms=20,
            delay_measured=True,
            stability_score=0.9,
        ),
        _verified(
            "20.0.0.1",
            90,
            security="reality",
            pbk="abcdefghijklmnopqrstuvwx",
            network="tcp",
        ),
    ]
    # normalize networks via structural_ok path
    for c in pool:
        if c.protocol == "vless":
            c.raw = (
                f"vless://11111111-1111-1111-1111-111111111111@{c.host}:443"
                f"?encryption=none&security={c.security}&type={c.network}"
                f"{'&pbk=' + c.pbk if c.pbk else ''}"
                f"{'&flow=' + c.flow if c.flow else ''}#n"
            )
    pack = select_censorship_pack(pool, 5)
    assert len(pack) <= 5
    quic_n = sum(1 for c in pack if strategy_class(c) == STRATEGY_QUIC_SPEED)
    assert quic_n <= 1
    slash = {f"{c.host.rsplit('.', 1)[0]}.0/24" if c.host[0].isdigit() else c.host for c in pack}
    # 10.0.0.1 and 10.0.0.2 must not both appear
    hosts = {c.host for c in pack}
    assert not ({"10.0.0.1", "10.0.0.2"} <= hosts)


def test_no_synthetic_delay_from_valid_txt(tmp_path: Path):
    valid = tmp_path / "valid.txt"
    valid.write_text(
        "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443?encryption=none#a\n"
        "vless://11111111-1111-1111-1111-111111111111@5.6.7.8:443?encryption=none#b\n",
        encoding="utf-8",
    )
    mapping = _collect_results(tmp_path, valid, tmp_path / "out.json", "")
    assert len(mapping) == 2
    assert all(v == UNMEASURED_DELAY_MS for v in mapping.values())


def test_iran_probe_boosts_score():
    a = _verified("1.1.1.1", 100)
    b = _verified("2.2.2.2", 100)
    b.iran_ok = True
    b.iran_delay_ms = 200
    assert censorship_score(b) > censorship_score(a)


def test_stability_and_iran_merge():
    cfg = _verified("8.8.8.8", 100)
    state: dict = {"fingerprints": {}, "quarantine": {}}
    apply_stability([cfg], state)
    assert cfg.stability_score > 0
    doc = {"updated_at": "", "probes": {}}
    merged = merge_probe_reports(
        doc,
        [{"fingerprint": cfg.fingerprint_key(), "ok": True, "delay_ms": 123, "ts": "2026-09-14T00:00:00Z"}],
    )
    meta = apply_iran_probes([cfg], merged)
    assert cfg.iran_ok is True
    assert meta["iran_pass"] == 1


def test_export_clash_singbox_smoke():
    cfg = parse_share_link(
        "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443"
        "?encryption=none&security=tls&type=tcp&sni=example.com#t"
    )
    assert cfg
    clash = export_clash([cfg])
    assert "proxies:" in clash
    sb = json.loads(export_singbox([cfg]))
    assert any(o.get("type") == "vless" for o in sb["outbounds"])


def test_export_socks_and_wireguard_singbox():
    socks = parse_share_link("socks5://user:pass@1.2.3.4:1080#s")
    wg = parse_share_link("wireguard://PRIVATEKEY@host.example:51820?publickey=PUB&address=10.0.0.2/32#wg")
    assert socks and wg
    sb = json.loads(export_singbox([socks, wg]))
    types = {o.get("type") for o in sb["outbounds"]}
    assert "socks" in types
    assert "wireguard" in types


def test_top_speed_helper():
    configs = [_verified(f"1.2.{i}.10", float(200 - i)) for i in range(5)]
    top = select_top_speed(configs, 3)
    assert top[0].median_delay_ms == 196
