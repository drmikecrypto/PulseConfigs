# Manual verification checklist (v2rayF)

Use this after GitHub Actions has published at least one successful `[auto]` commit.

## Prerequisites

- PulseConfigs repo pushed to GitHub with Actions enabled (contents: write)
- Latest `index.json` shows `counts.top5 >= 1` and `counts.verified >= 1`
- v2rayF desktop or Android build with **Free (Pulse)** button (or manual subscription import)

## Steps

1. Open `https://raw.githubusercontent.com/drmikecrypto/PulseConfigs/main/index.json`
2. Copy `v2rayF.top5_button` (Worker URL when configured, else raw)
3. In v2rayF: use **Free (Pulse)** **or** paste into the subscription URL field → Import
4. Expect **1–5** Free-tagged servers; each should show a **Free** chip and latency ≤150ms after on-device probe (or fewer if the network cannot)
5. Re-tap Free: good ≤150ms Free slots stay; only slow/failed Free slots rotate
6. Confirm user-imported servers are untouched
7. Import `v2rayF.recommended_subscription` (`verified/configs_base64.txt`) and confirm a larger list loads
8. Optionally import `features/reality.txt` and confirm REALITY entries include `pbk` and are not WS+REALITY

## Pass criteria

- [ ] Free button imports without wiping existing non-Free profiles
- [ ] At most 5 Free-tagged servers
- [ ] Re-tap replaces only Free slots with null/failed/>150ms latency
- [ ] No config with `security=reality` lacks `pbk`
- [ ] Tips doc matches slot + 150ms rules (`docs/tips/pulse-free-servers.md` in v2rayF)
