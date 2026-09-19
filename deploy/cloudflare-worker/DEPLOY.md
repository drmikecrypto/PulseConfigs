# Deploy PulseConfigs Cloudflare Worker

Yes — this means a **Cloudflare Worker** (edge JS), not a VPS.

## What it does

| Path | Purpose |
|------|---------|
| `GET /candidates.json`, `/top5.txt`, `/index.json`, … | Short-TTL mirror of GitHub raw (Iran-reachable) |
| `POST /refresh` | Rate-limited trigger of PulseConfigs GitHub Actions (`aggregate-now`) |
| `POST /probes/iran` | Optional forward to Germany collector |

## Deploy (recommended: Wrangler CLI)

From a terminal **you** can interact with (browser login):

```powershell
cd e:\GithubProject\PulseConfigs\deploy\cloudflare-worker
npx wrangler login
npx wrangler deploy
```

Then set the GitHub token used only for pool refresh (never put this in the app):

1. GitHub → Settings → Developer settings → Personal access tokens  
   Fine-grained token on `drmikecrypto/PulseConfigs` with **Actions: Read and write** (for `repository_dispatch`).
2. Store it on the Worker:

```powershell
npx wrangler secret put GITHUB_TOKEN
```

Optional Iran probe forward:

```powershell
npx wrangler secret put PROBE_SECRET
```

## After deploy

Wrangler prints a URL like:

```text
https://pulseconfigs-mirror.<subdomain>.workers.dev
```

Wire it into v2rayF:

- Set `AppSettings.PulseWorkerBase` to that origin (no trailing slash), **or**
- Set GitHub Actions variable `PULSE_WORKER_BASE` on PulseConfigs so `index.json` advertises Worker URLs.

Smoke test:

```text
GET  https://YOUR.workers.dev/health
GET  https://YOUR.workers.dev/candidates.json
POST https://YOUR.workers.dev/refresh
```

Free button works without Worker (raw/CDN fallback); Worker improves Iran reachability + soft pool refresh.
