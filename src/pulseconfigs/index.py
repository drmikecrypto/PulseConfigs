from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pulseconfigs.buckets import Buckets
from pulseconfigs.fetch import SourceResult


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_index(
    *,
    owner_repo: str,
    buckets: Buckets,
    files: dict[str, object],
    update_interval_minutes: int = 15,
) -> dict[str, Any]:
    base_raw = f"https://raw.githubusercontent.com/{owner_repo}/main"
    base_cdn = f"https://cdn.jsdelivr.net/gh/{owner_repo}@main"
    now = utc_now_iso()

    def url(rel: str) -> dict[str, str]:
        return {"raw": f"{base_raw}/{rel}", "cdn": f"{base_cdn}/{rel}", "path": rel}

    protocol_files = files.get("protocols") or {}
    feature_files = files.get("features") or {}

    return {
        "project": "PulseConfigs",
        "version": 1,
        "generated_at": now,
        "update_interval_minutes": update_interval_minutes,
        "owner_repo": owner_repo,
        "counts": {
            "all": len(buckets.all),
            "verified": len(buckets.verified),
            "fast": len(buckets.fast),
            "secure": len(buckets.secure),
            "top100": len(buckets.top100),
            "top5": len(buckets.top5),
            "reality": len(buckets.reality),
            "vision": len(buckets.vision),
            "by_protocol": {k: len(v) for k, v in buckets.by_protocol.items()},
        },
        "urls": {
            "top5": url("top5.txt") if files.get("top5") else None,
            "top100": url("top100.txt") if files.get("top100") else None,
            "verified_base64": url("verified/configs_base64.txt") if (files.get("verified") or {}).get("configs_base64.txt") else None,
            "verified": url("verified/configs.txt") if (files.get("verified") or {}).get("configs.txt") else None,
            "fast_base64": url("fast/configs_base64.txt") if (files.get("fast") or {}).get("configs_base64.txt") else None,
            "secure_base64": url("secure/configs_base64.txt") if (files.get("secure") or {}).get("configs_base64.txt") else None,
            "all_base64": url("all/configs_base64.txt") if (files.get("all") or {}).get("configs_base64.txt") else None,
            "reality": url("features/reality.txt") if feature_files.get("reality") else None,
            "vision": url("features/vision.txt") if feature_files.get("vision") else None,
            "protocols": {k: url(v) for k, v in protocol_files.items()},
        },
        "link_policy": {
            "prefer": "raw",
            "raw_max_age_seconds": 300,
            "cdn_worst_case_staleness_seconds": 43200,
            "mirrors": {"raw": base_raw, "jsdelivr": base_cdn},
        },
        "v2rayF": {
            "recommended_subscription": f"{base_raw}/verified/configs_base64.txt",
            "top5_button": f"{base_raw}/top5.txt",
            "top5_button_cdn": f"{base_cdn}/top5.txt",
        },
        "files": files,
    }


def build_health(
    *,
    buckets: Buckets,
    source_results: list[SourceResult],
    funnel: dict[str, int],
) -> dict[str, Any]:
    return {
        "generated_at": utc_now_iso(),
        "funnel": funnel,
        "sources": [
            {
                "id": r.source.id,
                "tier": r.source.tier,
                "ok": r.ok,
                "unique_yield": r.unique_yield,
                "bytes": r.bytes_len,
                "error": r.error,
                "url": r.source.url,
            }
            for r in source_results
        ],
        "verified_median_delay_ms": [
            c.median_delay_ms for c in buckets.verified if c.median_delay_ms is not None
        ][:200],
    }


def load_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"sources": {}, "disabled": []}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"sources": {}, "disabled": []}


def update_state(
    state: dict[str, Any],
    source_results: list[SourceResult],
    *,
    low_yield_threshold: int = 1,
    disable_after: int = 8,
) -> dict[str, Any]:
    sources = state.setdefault("sources", {})
    disabled = set(state.get("disabled") or [])
    for r in source_results:
        entry = sources.setdefault(r.source.id, {"low_streak": 0, "last_yield": 0, "history": []})
        entry["last_yield"] = r.unique_yield
        entry["last_ok"] = r.ok
        entry["history"] = (entry.get("history") or [])[-20:] + [r.unique_yield]
        if (not r.ok) or r.unique_yield < low_yield_threshold:
            entry["low_streak"] = int(entry.get("low_streak") or 0) + 1
        else:
            entry["low_streak"] = 0
        if entry["low_streak"] >= disable_after:
            disabled.add(r.source.id)
        elif r.ok and r.unique_yield >= low_yield_threshold:
            disabled.discard(r.source.id)
    state["disabled"] = sorted(disabled)
    state["updated_at"] = utc_now_iso()
    return state


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
