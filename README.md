# PulseConfigs

[![CI](https://github.com/drmikecrypto/PulseConfigs/actions/workflows/ci.yml/badge.svg)](https://github.com/drmikecrypto/PulseConfigs/actions/workflows/ci.yml)
[![Aggregate](https://github.com/drmikecrypto/PulseConfigs/actions/workflows/aggregate.yml/badge.svg)](https://github.com/drmikecrypto/PulseConfigs/actions/workflows/aggregate.yml)

**Free proxy configs for [v2rayF](https://github.com/drmikecrypto/v2rayF) and compatible clients** — auto-aggregated from public upstreams, structurally filtered, TCP/UDP-probed, L3-proven, and ranked with **censorship-aware diversity** (Iran L4 volunteer probes when online).

> **Not a fork.** Original pipeline, brand, and publish contract — designed around v2rayF’s dual-core import surface (Xray + sing-box).

---

## Start here

**Top 5 Free pack** (strategy-diverse; Iran-grounded when L4 probes are fresh). v2rayF’s **Free** button prefers `candidates.json`, then **probes on the user’s device** and keeps ≤5 servers under **150ms** locally — Actions RTT is not the user gate:

```text
https://raw.githubusercontent.com/drmikecrypto/PulseConfigs/main/candidates.json
https://raw.githubusercontent.com/drmikecrypto/PulseConfigs/main/top5.txt
```

**Top 5 speed** (US-runner latency only):

```text
https://raw.githubusercontent.com/drmikecrypto/PulseConfigs/main/top5_speed.txt
```

**Verified** subscription (recommended daily driver — base64):

```text
https://raw.githubusercontent.com/drmikecrypto/PulseConfigs/main/verified/configs_base64.txt
```

Machine-readable URLs live in [`index.json`](./index.json) under `v2rayF.*` and `iran_probe.*`.

### Mirrors (if raw GitHub is blocked)

```text
https://cdn.jsdelivr.net/gh/drmikecrypto/PulseConfigs@main/top5.txt
```

Prefer a **Cloudflare Worker** short-TTL mirror when deployed (`deploy/cloudflare-worker/`) — jsDelivr can lag ~12h.

---

## What you get

| Artifact | Meaning |
|----------|---------|
| `top5.txt` | Free pack: scored + diversity constraints; prefers fresh Iran L4 passes |
| `top5_speed.txt` | Verified, lowest US median delay, max 5 |
| `top5_iran.txt` | Explicit Iran-oriented selection |
| `candidates.json` | Shortlist for Iran phone L4 probes |
| `verified/` | Passed **all** L3 HTTP rounds |
| `fast/` | Verified and median delay &lt; 800 ms |
| `secure/` | Verified + forward secrecy, cert validation not disabled |
| `all/` | Deduped pool (mostly untested beyond L0–L2) |
| `protocols/*` | Per-protocol splits of `all` |
| `features/reality.txt` / `vision.txt` | REALITY / Vision subsets |
| `probes/iran.json` | Iran L4 pass/fail by fingerprint |
| `index.json` / `health.json` / `state.json` | Counters, funnel, source + stability + probe health |

Formats per tier: `configs.txt`, `configs_base64.txt`, `clash.yaml`, `singbox.json`.

### Protocols (v2rayF-compatible)

- **Xray:** VLESS, VMess, Trojan, Shadowsocks (no SIP003 plugins), SOCKS  
- **sing-box:** Hysteria2, TUIC, WireGuard, anytls  
- **Features:** REALITY (requires `pbk`; tcp/xhttp/grpc only), Vision (`flow=xtls-rprx-vision` on TCP), XHTTP

Incomplete REALITY, REALITY+WS, and Shadowsocks `plugin=` entries are **dropped**.

### Ranking (Free pack)

Score ≈ `0.35×stability + 0.25×strategy + 0.20×latency + 0.10×secure` plus Iran L4 boost/penalty.

Constraints (best-effort): ≥2 impersonation/TLS strategies, ≥1 CDN-style TLS, ≤1 QUIC, max 1 per IPv4 /24, prefer cert validation.

---

## Iran / China ops

| Role | Where |
|------|--------|
| US L0–L3 baseline | GitHub Actions |
| Collector + optional cron | Germany VPS (`deploy/vps/`, `python -m pulseconfigs.collector`) |
| Short-TTL mirror + probe forward | Cloudflare Worker (`deploy/cloudflare-worker/`) |
| Ground-truth L4 | Phone in Iran, VPN **off** (`deploy/termux-probe/probe_iran.py`) |

Free public nodes still churn under DPI. Diversity + refresh + client fragment/DoH (see v2rayF `docs/tips/pulse-free-servers.md`) matter as much as the aggregator.

---

## Clients

1. **v2rayF** (primary) — **Free (Pulse)** button or paste `top5.txt`  
2. v2rayNG / v2rayN / Hiddify / NekoBox  
3. Clash Meta / mihomo (`clash.yaml`)  
4. sing-box (`singbox.json`)

---

## Pipeline

```text
upstreams → fetch/decode → parse → L0/L1 + strategy tags → L2 TCP|UDP → L3 HTTP×3
  → stability window → Iran L4 overlay → censorship buckets → publish
```

GitHub Actions refreshes about every **15 minutes** (schedule + freshness gate).

### Local run

```bash
python -m pip install -e ".[dev]"
pytest -q
python -m pulseconfigs.cli run --out . --owner-repo drmikecrypto/PulseConfigs --skip-l3
```

For full L3 verification, install [`xray-knife`](https://github.com/lilendian0x00/xray-knife). Optional: `SING_BOX`, `MIHOMO`, `PULSE_WORKER_BASE`.

---

## Trust & safety

These are **public free proxies** scraped from third-party lists. Operators are unknown. Treat them as **untrusted**:

- Do not log into banks, email, or personal accounts over free nodes  
- Expect high churn; “verified” means the runner could fetch an HTTP resource through the proxy — not that the node is safe or works on your network  
- For privacy-sensitive use, run your own server

---

## License

MIT — see [LICENSE](./LICENSE). Upstream node operators retain whatever rights apply to their endpoints; this project only redistributes publicly posted share links for interoperability testing.
