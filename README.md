# PulseConfigs

[![CI](https://github.com/drmikecrypto/PulseConfigs/actions/workflows/ci.yml/badge.svg)](https://github.com/drmikecrypto/PulseConfigs/actions/workflows/ci.yml)
[![Aggregate](https://github.com/drmikecrypto/PulseConfigs/actions/workflows/aggregate.yml/badge.svg)](https://github.com/drmikecrypto/PulseConfigs/actions/workflows/aggregate.yml)

**Free proxy configs for [v2rayF](https://github.com/) and compatible clients** — auto-aggregated from public upstreams, structurally filtered, TCP-probed, and (when `xray-knife` is available) proven with real proxied HTTP checks.

> **Not a fork.** Original pipeline, brand, and publish contract — designed around v2rayF’s dual-core import surface (Xray + sing-box).

---

## Start here

**Top 5** (fastest verified — used by the future v2rayF “Free servers” button):

```text
https://raw.githubusercontent.com/drmikecrypto/PulseConfigs/main/top5.txt
```

**Verified** subscription (recommended daily driver — base64):

```text
https://raw.githubusercontent.com/drmikecrypto/PulseConfigs/main/verified/configs_base64.txt
```

Machine-readable URLs also live in [`index.json`](./index.json) under `v2rayF.top5_button` and `v2rayF.recommended_subscription`.

### Mirror (if raw GitHub is blocked)

```text
https://cdn.jsdelivr.net/gh/drmikecrypto/PulseConfigs@main/top5.txt
https://cdn.jsdelivr.net/gh/drmikecrypto/PulseConfigs@main/verified/configs_base64.txt
```

Prefer **raw** when you can (fresher). jsDelivr can lag up to ~12h on the branch ref.

---

## What you get

| Artifact | Meaning |
|----------|---------|
| `top5.txt` | Verified configs, lowest median delay, max **5** |
| `top100.txt` | Same idea, max 100 |
| `verified/` | Passed **all** L3 HTTP rounds |
| `fast/` | Verified and median delay &lt; 800 ms |
| `secure/` | Verified + forward secrecy, cert validation not disabled |
| `all/` | Deduped pool (mostly untested beyond L0–L2) |
| `protocols/*` | Per-protocol splits of `all` |
| `features/reality.txt` / `vision.txt` | REALITY / Vision subsets |
| `index.json` / `health.json` / `state.json` | Counters, funnel, source health |

Formats per tier: `configs.txt`, `configs_base64.txt`, `clash.yaml`, `singbox.json`.

### Protocols (v2rayF-compatible)

- **Xray:** VLESS, VMess, Trojan, Shadowsocks (no SIP003 plugins), SOCKS  
- **sing-box:** Hysteria2, TUIC, WireGuard, anytls  
- **Features:** REALITY (requires `pbk`), Vision (`flow=xtls-rprx-vision`)

Incomplete REALITY links and Shadowsocks `plugin=` entries are **dropped**, not published.

---

## Clients

1. **v2rayF** (primary) — paste a subscription URL or `top5.txt`  
2. v2rayNG / v2rayN / Hiddify / NekoBox  
3. Clash Meta / mihomo (`clash.yaml`)  
4. sing-box (`singbox.json`)

---

## Pipeline

```text
upstreams → fetch/decode → parse → L0/L1 filter + dedupe → L2 TCP → L3 HTTP×3 → buckets → publish
```

GitHub Actions refreshes about every **15 minutes** (schedule + freshness gate).

### Local run

```bash
python -m pip install -e ".[dev]"
pytest -q
python -m pulseconfigs.cli run --out . --owner-repo drmikecrypto/PulseConfigs --skip-l3
```

For full L3 verification, install [`xray-knife`](https://github.com/lilendian0x00/xray-knife) and put it on `PATH` (or set `XRAY_KNIFE`). Optional: `SING_BOX`, `MIHOMO` for client config validation.

---

## Manual check in v2rayF (before the in-app button)

1. Wait for a CI run that produces non-empty `top5.txt` and `verified/`.  
2. Open v2rayF → paste the **raw** `top5.txt` URL into the subscription field → Import.  
3. Confirm **≤ 5** servers appear and Test/Connect works on at least one.  
4. Repeat with `verified/configs_base64.txt`.

Phase 2 (separate change in the v2rayF app): a **Free servers (Pulse)** button that fetches `top5.txt` automatically.

---

## Trust & safety

These are **public free proxies** scraped from third-party lists. Operators are unknown. Treat them as **untrusted**:

- Do not log into banks, email, or personal accounts over free nodes  
- Expect high churn; “verified” means the runner could fetch an HTTP resource through the proxy — not that the node is safe or works on your network  
- For privacy-sensitive use, run your own server

---

## License

MIT — see [LICENSE](./LICENSE). Upstream node operators retain whatever rights apply to their endpoints; this project only redistributes publicly posted share links for interoperability testing.
