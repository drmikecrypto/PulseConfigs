from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from pulseconfigs.buckets import build_buckets
from pulseconfigs.export import export_all
from pulseconfigs.fetch import fetch_all_sync
from pulseconfigs.filter import filter_l0_l1
from pulseconfigs.index import build_health, build_index, load_state, update_state, write_json
from pulseconfigs.normalize import apply_brand
from pulseconfigs.prove import prove_l3_sync, xray_knife_path
from pulseconfigs.reachability import probe_l2_sync
from pulseconfigs.sources import active_sources
from pulseconfigs.validate import validate_tier_artifacts


def _fresh_enough(index_path: Path, minutes: float = 12.0) -> bool:
    if not index_path.exists():
        return False
    try:
        data = json.loads(index_path.read_text(encoding="utf-8"))
        ts = data.get("generated_at")
        if not ts:
            return False
        generated = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - generated).total_seconds()
        return age < minutes * 60
    except Exception:
        return False


def run_pipeline(
    out_dir: Path,
    *,
    owner_repo: str,
    skip_l3: bool = False,
    l2_timeout: float = 3.0,
    max_l3: int = 2500,
    brand: str = "PulseConfigs",
) -> int:
    state_path = out_dir / "state.json"
    state = load_state(state_path)
    disabled = set(state.get("disabled") or [])
    sources = active_sources(disabled)

    print(f"[pulse] fetching {len(sources)} sources…")
    results = fetch_all_sync(sources)
    pooled = []
    for r in results:
        status = "ok" if r.ok else f"ERR {r.error}"
        print(f"  - {r.source.id}: yield={r.unique_yield} ({status})")
        pooled.extend(r.configs)

    print(f"[pulse] raw pooled={len(pooled)}")
    accepted, rejected = filter_l0_l1(pooled)
    print(f"[pulse] after L0/L1={len(accepted)} rejected={len(rejected)}")

    print("[pulse] L2 TCP probe…")
    accepted = probe_l2_sync(accepted, timeout=l2_timeout)
    l2_ok = [c for c in accepted if c.l2_ok]
    print(f"[pulse] L2 open={len(l2_ok)}")

    if skip_l3 or os.environ.get("PULSE_SKIP_L3") == "1":
        print("[pulse] L3 skipped")
    else:
        knife = xray_knife_path()
        if not knife:
            print("[pulse] WARNING: xray-knife not found; verified/top5 will be empty")
        print(f"[pulse] L3 prove (knife={knife})…")
        accepted = prove_l3_sync(accepted, max_candidates=max_l3)

    apply_brand(accepted, brand=brand)
    buckets = build_buckets(accepted, rejected)
    print(
        f"[pulse] buckets all={len(buckets.all)} verified={len(buckets.verified)} "
        f"fast={len(buckets.fast)} top5={len(buckets.top5)}"
    )

    files = export_all(out_dir, buckets)

    # Validate verified artifacts when present
    errors: list[str] = []
    for tier in ("verified", "fast", "secure", "all"):
        tier_dir = out_dir / tier
        if tier_dir.is_dir():
            errors.extend(validate_tier_artifacts(tier_dir, fail_closed=True))
    if errors and os.environ.get("PULSE_REQUIRE_VALIDATORS") == "1":
        print("[pulse] validation failed:")
        for e in errors:
            print(" ", e)
        return 2
    for e in errors:
        print(f"[pulse] validation warning: {e}")

    funnel = {
        "fetched": len(pooled),
        "l0_l1": len(accepted) + len([c for c in rejected]),
        "accepted_structural": len(accepted),
        "rejected_structural": len(rejected),
        "l2_ok": len(l2_ok),
        "verified": len(buckets.verified),
        "fast": len(buckets.fast),
        "secure": len(buckets.secure),
        "top5": len(buckets.top5),
    }
    index = build_index(owner_repo=owner_repo, buckets=buckets, files=files)
    health = build_health(buckets=buckets, source_results=results, funnel=funnel)
    state = update_state(state, results)
    write_json(out_dir / "index.json", index)
    write_json(out_dir / "health.json", health)
    write_json(state_path, state)
    print(f"[pulse] wrote artifacts to {out_dir}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pulseconfigs", description="PulseConfigs aggregator")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser("run", help="Fetch, test, and publish artifacts")
    p_run.add_argument("--out", type=Path, default=Path("."))
    p_run.add_argument(
        "--owner-repo",
        default=os.environ.get("PULSE_OWNER_REPO", "PulseConfigs/PulseConfigs"),
    )
    p_run.add_argument("--skip-l3", action="store_true")
    p_run.add_argument("--max-l3", type=int, default=2500)
    p_run.add_argument("--l2-timeout", type=float, default=3.0)

    p_fresh = sub.add_parser("freshness", help="Exit 0 if index.json is fresh enough to skip")
    p_fresh.add_argument("--index", type=Path, default=Path("index.json"))
    p_fresh.add_argument("--minutes", type=float, default=12.0)

    p_parse = sub.add_parser("parse-file", help="Parse a local subscription file and print counts")
    p_parse.add_argument("path", type=Path)

    args = parser.parse_args(argv)

    if args.cmd == "freshness":
        if _fresh_enough(args.index, args.minutes):
            print("fresh")
            return 0
        print("stale")
        return 1

    if args.cmd == "parse-file":
        from pulseconfigs.filter import filter_l0_l1
        from pulseconfigs.parse import parse_subscription_text

        text = args.path.read_text(encoding="utf-8", errors="ignore")
        cfgs = parse_subscription_text(text)
        ok, bad = filter_l0_l1(cfgs)
        print(json.dumps({"parsed": len(cfgs), "accepted": len(ok), "rejected": len(bad)}, indent=2))
        return 0

    if args.cmd == "run":
        return run_pipeline(
            args.out,
            owner_repo=args.owner_repo,
            skip_l3=args.skip_l3,
            l2_timeout=args.l2_timeout,
            max_l3=args.max_l3,
        )

    return 1


if __name__ == "__main__":
    sys.exit(main())
