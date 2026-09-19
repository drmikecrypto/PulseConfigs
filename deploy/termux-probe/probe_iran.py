#!/usr/bin/env python3
"""Iran L4 volunteer probe for Termux (phone inside Iran).

Rules:
  - Disconnect Germany / any system VPN before running.
  - Prefer cellular on hard-filter days; also sample Wi-Fi.
  - Only probes the published shortlist (not the full 18k pool).

Install (Termux):
  pkg install python xray-core  # or install sing-box / xray binary on PATH
  pip install httpx
  export PULSE_API=https://YOUR_WORKER_OR_VPS
  export PULSE_PROBE_SECRET=...
  python probe_iran.py

Cron-ish: termux-job-scheduler or while-loop every 20m while charging.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

API = os.environ.get("PULSE_API", "").rstrip("/")
SECRET = os.environ.get("PULSE_PROBE_SECRET", "")
LIMIT = int(os.environ.get("PULSE_PROBE_LIMIT", "40"))
DEST = os.environ.get("PULSE_PROBE_DEST", "https://www.cloudflare.com/cdn-cgi/trace")
TIMEOUT = int(os.environ.get("PULSE_PROBE_TIMEOUT", "12"))
MIN_BATTERY = int(os.environ.get("PULSE_MIN_BATTERY", "20"))
ISP_HINT = os.environ.get("PULSE_ISP_HINT", "")


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def http_json(method: str, url: str, body: dict | None = None) -> dict:
    data = None if body is None else json.dumps(body).encode("utf-8")
    headers = {"User-Agent": "PulseIranProbe/1.0", "Accept": "application/json"}
    if SECRET:
        headers["Authorization"] = f"Bearer {SECRET}"
        headers["X-Pulse-Secret"] = SECRET
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = Request(url, data=data, headers=headers, method=method)
    with urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def battery_ok() -> bool:
    """Best-effort Termux battery check; allow if unknown."""
    bin_path = shutil.which("termux-battery-status")
    if not bin_path:
        return True
    try:
        out = subprocess.check_output([bin_path], text=True, timeout=5)
        data = json.loads(out)
        pct = int(data.get("percentage") or 100)
        charging = str(data.get("status") or "").lower() in {"charging", "full"}
        if charging:
            return True
        return pct >= MIN_BATTERY
    except Exception:
        return True


def vpn_warn() -> None:
    # Android: if tun0 exists, likely a VPN is up
    if Path("/sys/class/net/tun0").exists() or Path("/sys/class/net/ppp0").exists():
        print(
            "WARNING: tun0/ppp0 present — disconnect system VPN so probes use Iran ISP path.",
            file=sys.stderr,
        )


def which_core() -> tuple[str, str] | None:
    for name in ("xray", "xray-core", "sing-box", "singbox"):
        p = shutil.which(name)
        if p:
            kind = "singbox" if "sing" in name else "xray"
            return p, kind
    knife = shutil.which("xray-knife") or os.environ.get("XRAY_KNIFE")
    if knife:
        return knife, "knife"
    return None


def prove_one(core: tuple[str, str], link: str) -> tuple[bool, float | None]:
    path, kind = core
    if kind == "knife":
        with tempfile.TemporaryDirectory(prefix="pulse-ir-") as td:
            inp = Path(td) / "in.txt"
            valid = Path(td) / "valid.txt"
            inp.write_text(link + "\n", encoding="utf-8")
            cmd = [path, "http", "-f", str(inp), "-o", str(valid), "-d", DEST, "-t", str(TIMEOUT * 1000)]
            try:
                subprocess.run(cmd, capture_output=True, timeout=TIMEOUT + 15, check=False)
            except Exception:
                return False, None
            if valid.exists() and valid.read_text(encoding="utf-8", errors="ignore").strip():
                return True, None
            return False, None

    # Without a full URI→config converter on-device, knife is preferred.
    # Fallback: treat as fail with clear message once.
    print("NOTE: install xray-knife for accurate URI proves; core-only mode limited.", file=sys.stderr)
    return False, None


def main() -> int:
    if not API:
        print("Set PULSE_API to your Worker or Germany collector base URL", file=sys.stderr)
        return 2
    if not battery_ok():
        print(f"Battery below {MIN_BATTERY}% and not charging — skip")
        return 0
    vpn_warn()
    core = which_core()
    if not core:
        print("No xray-knife/xray/sing-box on PATH", file=sys.stderr)
        return 2

    cand = http_json("GET", f"{API}/candidates?limit={LIMIT}")
    rows = cand.get("candidates") or []
    print(f"[probe] {len(rows)} candidates via {API}")
    reports = []
    for row in rows:
        link = row.get("raw") or ""
        fp = row.get("fingerprint") or ""
        if not link:
            continue
        t0 = time.time()
        ok, delay = prove_one(core, link)
        elapsed = (time.time() - t0) * 1000.0
        reports.append(
            {
                "fingerprint": fp,
                "ok": ok,
                "delay_ms": delay if delay is not None else (elapsed if ok else None),
                "isp_hint": ISP_HINT,
                "ts": utc_now(),
            }
        )
        print(f"  {'OK' if ok else 'FAIL'} {fp[:24] or link[:40]}…")

    if not reports:
        print("No reports to upload")
        return 0
    result = http_json("POST", f"{API}/probes/iran", {"reports": reports})
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
