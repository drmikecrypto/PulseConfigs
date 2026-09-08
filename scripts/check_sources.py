#!/usr/bin/env python3
"""Print yield for each configured upstream source."""

from pulseconfigs.fetch import fetch_all_sync
from pulseconfigs.sources import active_sources


def main() -> None:
    results = fetch_all_sync(active_sources(), timeout=25.0)
    ok = sum(1 for r in results if r.ok and r.unique_yield > 0)
    print(f"sources_ok {ok}/{len(results)}")
    for r in sorted(results, key=lambda x: -x.unique_yield):
        err = (r.error or "")[:80]
        print(f"{r.source.id:24} yield={r.unique_yield:5} ok={r.ok} {err}")


if __name__ == "__main__":
    main()
