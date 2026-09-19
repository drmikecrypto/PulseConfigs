from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pulseconfigs.models import ProxyConfig

# Iran L4 results older than this are treated as stale for Free-button ranking.
IRAN_FRESH_SECONDS = 45 * 60


def _parse_iso(ts: str) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def load_iran_probes(path: Path) -> dict[str, Any]:
    """Load probes/iran.json or empty structure."""
    if not path.exists():
        return {"updated_at": "", "probes": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"updated_at": "", "probes": {}}
    if not isinstance(data, dict):
        return {"updated_at": "", "probes": {}}
    data.setdefault("probes", {})
    data.setdefault("updated_at", "")
    return data


def apply_iran_probes(configs: list[ProxyConfig], probes_doc: dict[str, Any]) -> dict[str, Any]:
    """Attach Iran L4 fields onto configs. Returns summary for health.json."""
    probes: dict[str, Any] = probes_doc.get("probes") or {}
    now = datetime.now(timezone.utc)
    updated = _parse_iso(str(probes_doc.get("updated_at") or ""))
    age = (now - updated).total_seconds() if updated else None
    fresh = age is not None and age <= IRAN_FRESH_SECONDS

    iran_ok_n = 0
    iran_fail_n = 0
    for cfg in configs:
        row = probes.get(cfg.fingerprint_key())
        if not row or not isinstance(row, dict):
            cfg.iran_ok = None
            cfg.iran_delay_ms = None
            cfg.iran_probed_at = ""
            continue
        ok = bool(row.get("ok"))
        cfg.iran_ok = ok
        delay = row.get("delay_ms")
        try:
            cfg.iran_delay_ms = float(delay) if delay is not None else None
        except (TypeError, ValueError):
            cfg.iran_delay_ms = None
        cfg.iran_probed_at = str(row.get("ts") or "")
        if ok:
            iran_ok_n += 1
        else:
            iran_fail_n += 1

    return {
        "probe_online": bool(fresh),
        "probe_age_seconds": int(age) if age is not None else None,
        "iran_probed": iran_ok_n + iran_fail_n,
        "iran_pass": iran_ok_n,
        "iran_fail": iran_fail_n,
        "iran_pass_rate": (iran_ok_n / (iran_ok_n + iran_fail_n)) if (iran_ok_n + iran_fail_n) else None,
        "stale_probe": not fresh,
        "updated_at": probes_doc.get("updated_at") or "",
    }


def merge_probe_reports(
    probes_doc: dict[str, Any],
    reports: list[dict[str, Any]],
) -> dict[str, Any]:
    """Merge POST /probes/iran body rows into the probes document."""
    probes: dict[str, Any] = dict(probes_doc.get("probes") or {})
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for row in reports:
        fp = str(row.get("fingerprint") or "")
        if not fp:
            continue
        probes[fp] = {
            "ok": bool(row.get("ok")),
            "delay_ms": row.get("delay_ms"),
            "isp_hint": row.get("isp_hint") or "",
            "ts": str(row.get("ts") or now),
        }
    return {"updated_at": now, "probes": probes}
