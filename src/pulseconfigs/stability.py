from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from pulseconfigs.models import ProxyConfig

HISTORY_LEN = 12
QUARANTINE_HOURS = 3.0
STABLE_PASS_FLOOR = 0.5


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(ts: str) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def apply_stability(
    configs: list[ProxyConfig],
    state: dict[str, Any],
) -> dict[str, Any]:
    """Update per-fingerprint pass history and set cfg.stability_score.

    Quarantined fingerprints (recent fail streak) get a low score and are tagged
    in state['quarantine'] until QUARANTINE_HOURS elapse.
    """
    fp_state: dict[str, Any] = state.setdefault("fingerprints", {})
    quarantine: dict[str, str] = dict(state.get("quarantine") or {})
    now = _utc_now()
    now_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Expire old quarantine entries
    fresh_q: dict[str, str] = {}
    for key, until in quarantine.items():
        until_dt = _parse_iso(until)
        if until_dt and until_dt > now:
            fresh_q[key] = until

    for cfg in configs:
        key = cfg.fingerprint_key()
        entry = fp_state.setdefault(key, {"history": [], "last_ok": False})
        history: list[int] = list(entry.get("history") or [])
        passed = 1 if cfg.verified else 0
        history = (history + [passed])[-HISTORY_LEN:]
        entry["history"] = history
        entry["last_ok"] = bool(passed)
        entry["updated_at"] = now_iso

        if history:
            cfg.stability_score = sum(history) / len(history)
        else:
            cfg.stability_score = 0.5

        # Enter quarantine on verified→fail transition after prior success
        if not passed and len(history) >= 2 and history[-2] == 1:
            until = (now + timedelta(hours=QUARANTINE_HOURS)).strftime("%Y-%m-%dT%H:%M:%SZ")
            fresh_q[key] = until

        if key in fresh_q:
            cfg.stability_score = min(cfg.stability_score, 0.15)

    state["fingerprints"] = fp_state
    state["quarantine"] = fresh_q
    return state


def is_quarantined(cfg: ProxyConfig, state: dict[str, Any]) -> bool:
    q = state.get("quarantine") or {}
    until = q.get(cfg.fingerprint_key())
    until_dt = _parse_iso(until or "")
    return bool(until_dt and until_dt > _utc_now())
