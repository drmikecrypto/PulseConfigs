# Security Policy

## Untrusted free proxies

PulseConfigs redistributes **publicly posted** proxy share links from third-party aggregators. Nodes are operated by unknown parties.

- Do **not** treat published configs as private or trustworthy
- Do **not** send credentials, personal data, or sensitive traffic through free nodes
- Report malicious or abusive upstream **source URLs** (not individual dead configs) via GitHub Issues

## Probe ingest

Iran L4 volunteer probes (`POST /probes/iran`) require a shared secret (`PULSE_PROBE_SECRET`). Store fingerprints and pass/fail only — do not log full share-links in Worker analytics.

## Supply chain

CI installs pinned third-party binaries (`sing-box`, `mihomo`, `xray-knife`) to validate and probe configs. Review workflow pins before enabling `PULSE_REQUIRE_VALIDATORS=1`.

## Vulnerability reporting

Open a private security advisory or GitHub Issue describing the problem. Do not include live credentials.
