# Termux Iran L4 probe

Your phone **can** act as a volunteer probe **only if**:

1. System VPN / Germany tunnel is **disconnected**
2. Traffic uses cellular or local Wi‑Fi (MCI / Irancell / TCI, etc.)
3. You only probe the published shortlist (`/candidates`), not thousands of nodes

## Setup

```bash
pkg update && pkg install python
pip install httpx   # optional; script uses urllib
# Install xray-knife binary on PATH (recommended)
export PULSE_API=https://YOUR_WORKER_OR_COLLECTOR
export PULSE_PROBE_SECRET='same-as-vps'
export PULSE_ISP_HINT=mci   # or irancell / tci-wifi
python probe_iran.py
```

Schedule every 15–30 minutes while charging (`termux-job-scheduler` or a loop). Skip when battery &lt; 20%.

After upload, the next PulseConfigs `run` merges `probes/iran.json` into Free `top5.txt`.
