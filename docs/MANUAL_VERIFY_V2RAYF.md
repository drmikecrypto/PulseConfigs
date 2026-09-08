# Manual verification checklist (v2rayF)

Use this after GitHub Actions has published at least one successful `[auto]` commit.

## Prerequisites

- PulseConfigs repo pushed to GitHub with Actions enabled (contents: write)
- Latest `index.json` shows `counts.top5 >= 1` and `counts.verified >= 1`
- v2rayF desktop or Android build that can import subscriptions

## Steps

1. Open `https://raw.githubusercontent.com/drmikecrypto/PulseConfigs/main/index.json`
2. Copy `v2rayF.top5_button`
3. In v2rayF, paste into the subscription URL field and import
4. Expect **1–5** servers; remarks should contain `@PulseConfigs`
5. Run **Test** on each; at least one should succeed from your network (US-runner verified ≠ Iran/local verified)
6. Import `v2rayF.recommended_subscription` (`verified/configs_base64.txt`) and confirm a larger list loads
7. Optionally import `features/reality.txt` and confirm REALITY entries include `pbk`

## Pass criteria

- [ ] `top5.txt` imports without wiping existing profiles unexpectedly (append behavior as designed in app)
- [ ] No config with `security=reality` lacks `pbk`
- [ ] No Shadowsocks line contains `plugin=`
- [ ] Clash / sing-box files from `verified/` open in their respective clients (optional)

Only after this checklist passes should the v2rayF **Free servers (Pulse)** button be implemented.
