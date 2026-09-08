from __future__ import annotations

import base64
import json

import pytest

from pulseconfigs.buckets import build_buckets
from pulseconfigs.export import export_clash, export_singbox
from pulseconfigs.filter import filter_l0_l1
from pulseconfigs.models import ProxyConfig
from pulseconfigs.normalize import structural_ok
from pulseconfigs.parse import parse_share_link, parse_subscription_text


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
    ok, reason = structural_ok(cfg)
    assert ok, reason


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


def test_buckets_top5():
    configs = []
    for i in range(10):
        c = ProxyConfig(
            raw=f"vless://11111111-1111-1111-1111-111111111111@1.2.3.{i}:443?encryption=none#n{i}",
            protocol="vless",
            host=f"1.2.3.{i}",
            port=443,
            security="tls",
            l3_rounds=3,
            l3_passes=3,
            median_delay_ms=float(100 + i),
            delays_ms=[100 + i],
        )
        configs.append(c)
    # one unverified
    configs.append(
        ProxyConfig(
            raw="vless://11111111-1111-1111-1111-111111111111@9.9.9.9:443?encryption=none#x",
            protocol="vless",
            host="9.9.9.9",
            port=443,
            l3_rounds=3,
            l3_passes=1,
            median_delay_ms=50,
        )
    )
    b = build_buckets(configs)
    assert len(b.verified) == 10
    assert len(b.top5) == 5
    assert b.top5[0].median_delay_ms == 100
    assert len(b.fast) == 10


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
