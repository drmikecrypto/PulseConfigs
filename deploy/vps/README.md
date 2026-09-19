# Germany VPS control plane

## Role

- Host optional full `pulseconfigs run` cron (or pull published artifacts)
- Run the collector API for Iran phone L4 ingest
- Optionally git-push updated `probes/iran.json` back to GitHub

## Quick start

```bash
git clone https://github.com/drmikecrypto/PulseConfigs.git /opt/PulseConfigs
cd /opt/PulseConfigs
python3 -m venv .venv && . .venv/bin/activate
pip install -e .

export PULSE_REPO_ROOT=/opt/PulseConfigs
export PULSE_PROBE_SECRET='generate-a-long-random-secret'
# optional: Cloudflare Worker base for index.json links
export PULSE_WORKER_BASE=https://pulseconfigs-mirror.<you>.workers.dev

# Collector (systemd or screen)
python -m pulseconfigs.collector --host 0.0.0.0 --port 8787
```

Put nginx/caddy TLS in front; expose only `/candidates`, `/probes/iran`, `/health`, and artifact GETs.

## Cron aggregator (optional)

```cron
*/15 * * * * cd /opt/PulseConfigs && . .venv/bin/activate && \
  python -m pulseconfigs.cli run --out /opt/PulseConfigs \
  --owner-repo drmikecrypto/PulseConfigs --max-l3 1200 \
  >> /var/log/pulseconfigs.log 2>&1
```

After Iran probes land in `probes/iran.json`, the next `run` merges them into Free `top5.txt`.

## Publish probes to GitHub

If Actions owns the tree, commit from VPS:

```bash
cd /opt/PulseConfigs
git add probes/iran.json
git commit -m "[auto] Iran L4 probe refresh"
git push
```

Or let the next GHA aggregate pull `probes/iran.json` from the repo (preferred once committed).
