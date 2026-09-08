from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import statistics
import subprocess
import tempfile
from pathlib import Path

from pulseconfigs.models import ProxyConfig


def _which(name: str) -> str | None:
    return shutil.which(name)


def xray_knife_path() -> str | None:
    return os.environ.get("XRAY_KNIFE") or _which("xray-knife") or _which("xray-knife.exe")


_DELAY_RE = re.compile(r"(\d+(?:\.\d+)?)\s*ms", re.I)


async def _run_knife_round(
    knife: str,
    links: list[str],
    *,
    timeout_s: float,
    dest: str,
) -> dict[str, float]:
    """Return map bare_link (no fragment) -> delay_ms for successes."""
    if not links:
        return {}
    with tempfile.TemporaryDirectory(prefix="pulse-l3-") as td:
        td_path = Path(td)
        inp = td_path / "in.txt"
        valid = td_path / "valid.txt"
        out_json = td_path / "out.json"
        inp.write_text("\n".join(links) + "\n", encoding="utf-8")

        cmds = [
            # Modern xray-knife: writes working links to valid.txt (fastest first)
            [
                knife,
                "http",
                "-f",
                str(inp),
                "-o",
                str(valid),
                "-d",
                dest,
                "-t",
                str(int(timeout_s * 1000)),
            ],
            [
                knife,
                "http",
                "-f",
                str(inp),
                "-o",
                str(valid),
                "--url",
                dest,
            ],
            [
                knife,
                "http",
                "-f",
                str(inp),
            ],
            [
                knife,
                "http",
                "-f",
                str(inp),
                "-o",
                str(out_json),
            ],
        ]

        cwd = td
        for cmd in cmds:
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    cwd=cwd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                try:
                    stdout, stderr = await asyncio.wait_for(
                        proc.communicate(),
                        timeout=timeout_s * max(10, len(links) // 15 + 3),
                    )
                except TimeoutError:
                    proc.kill()
                    await proc.wait()
                    continue

                mapping = _collect_results(td_path, valid, out_json, stdout.decode(errors="ignore"))
                if mapping:
                    return mapping
            except FileNotFoundError:
                return {}
            except Exception:
                continue
    return {}


def _bare(link: str) -> str:
    return link.strip().split("#", 1)[0]


def _collect_results(
    td: Path,
    valid: Path,
    out_json: Path,
    stdout: str,
) -> dict[str, float]:
    results: dict[str, float] = {}

    # Prefer JSON output if present
    for candidate in (out_json, td / "results.json", td / "out.json"):
        if candidate.exists() and candidate.stat().st_size > 0:
            parsed = _parse_knife_json(candidate.read_text(encoding="utf-8", errors="ignore"))
            if parsed:
                return parsed

    # valid.txt — ordered by speed; assign synthetic increasing delays
    for name in ("valid.txt", "ok.txt", "alive.txt"):
        path = td / name if name != "valid.txt" else valid
        if not path.exists():
            path = td / name
        if path.exists() and path.stat().st_size > 0:
            lines = [ln.strip() for ln in path.read_text(encoding="utf-8", errors="ignore").splitlines() if ln.strip() and "://" in ln]
            for i, link in enumerate(lines):
                results[_bare(link)] = float(50 + i * 5)
            if results:
                return results

    # Parse stdout lines that contain links + ms
    for line in stdout.splitlines():
        if "://" not in line:
            continue
        m = _DELAY_RE.search(line)
        # extract uri
        for part in line.split():
            if "://" in part:
                uri = part.strip().rstrip(",;")
                delay = float(m.group(1)) if m else 9999.0
                results[_bare(uri)] = delay
                break
    return results


def _parse_knife_json(text: str) -> dict[str, float]:
    text = text.strip()
    if not text:
        return {}
    results: dict[str, float] = {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            _row_to_map(row, results)
        return results

    rows = data if isinstance(data, list) else data.get("results") or data.get("data") or []
    if isinstance(data, dict) and not rows and ("config" in data or "link" in data):
        rows = [data]
    for row in rows:
        if isinstance(row, dict):
            _row_to_map(row, results)
    return results


def _row_to_map(row: dict, results: dict[str, float]) -> None:
    link = str(row.get("config") or row.get("link") or row.get("uri") or row.get("Config") or "")
    delay = row.get("delay") or row.get("latency") or row.get("ms") or row.get("Delay")
    ok = row.get("status") in {True, "ok", "OK", 1, "alive"} or row.get("ok") is True
    if not link:
        return
    if delay is not None:
        try:
            results[_bare(link)] = float(delay)
        except (TypeError, ValueError):
            results[_bare(link)] = 9999.0
    elif ok:
        results[_bare(link)] = 9999.0


async def prove_l3(
    configs: list[ProxyConfig],
    *,
    rounds: int = 3,
    timeout_s: float = 8.0,
    dest: str = "https://www.cloudflare.com/cdn-cgi/trace",
    max_candidates: int = 2500,
) -> list[ProxyConfig]:
    """Run L3 proxy HTTP tests. Only L2-ok configs are candidates."""
    candidates = [c for c in configs if c.l2_ok][:max_candidates]
    knife = xray_knife_path()
    for cfg in configs:
        cfg.l3_rounds = rounds
        cfg.l3_passes = 0
        cfg.delays_ms = []
        cfg.median_delay_ms = None

    if not knife:
        for cfg in candidates:
            cfg.reject_reason = cfg.reject_reason or "l3_no_xray_knife"
        return configs

    for r in range(rounds):
        links = [c.raw for c in candidates]
        if r:
            await asyncio.sleep(0.5)
        mapping = await _run_knife_round(knife, links, timeout_s=timeout_s, dest=dest)
        for cfg in candidates:
            delay = mapping.get(_bare(cfg.raw))
            if delay is not None:
                cfg.l3_passes += 1
                cfg.delays_ms.append(float(delay))

    for cfg in candidates:
        if cfg.delays_ms:
            cfg.median_delay_ms = float(statistics.median(cfg.delays_ms))
        if cfg.l3_passes < rounds:
            cfg.reject_reason = cfg.reject_reason or "l3_incomplete"

    return configs


def prove_l3_sync(configs: list[ProxyConfig], **kwargs: object) -> list[ProxyConfig]:
    return asyncio.run(prove_l3(configs, **kwargs))  # type: ignore[arg-type]


def run_cmd(cmd: list[str], timeout: float = 60.0) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return p.returncode, p.stdout, p.stderr
    except Exception as exc:  # noqa: BLE001
        return 1, "", str(exc)
