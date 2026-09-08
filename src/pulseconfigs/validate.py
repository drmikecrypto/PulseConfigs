from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path


def _which(name: str) -> str | None:
    return shutil.which(name)


def validate_singbox(path: Path) -> tuple[bool, str]:
    binary = os.environ.get("SING_BOX") or _which("sing-box") or _which("sing-box.exe")
    if not binary:
        return True, "sing-box not installed; skipped"
    try:
        p = subprocess.run(
            [binary, "check", "-c", str(path)],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if p.returncode != 0:
            return False, (p.stderr or p.stdout or "sing-box check failed")[:2000]
        return True, "ok"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def validate_mihomo(path: Path) -> tuple[bool, str]:
    binary = os.environ.get("MIHOMO") or _which("mihomo") or _which("mihomo.exe") or _which("clash")
    if not binary:
        return True, "mihomo not installed; skipped"
    try:
        p = subprocess.run(
            [binary, "-t", "-f", str(path)],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if p.returncode != 0:
            return False, (p.stderr or p.stdout or "mihomo test failed")[:2000]
        return True, "ok"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def validate_tier_artifacts(tier_dir: Path, *, fail_closed: bool = True) -> list[str]:
    """Validate clash.yaml / singbox.json if present. Returns error messages."""
    errors: list[str] = []
    sb = tier_dir / "singbox.json"
    clash = tier_dir / "clash.yaml"
    if sb.exists():
        ok, msg = validate_singbox(sb)
        if not ok:
            errors.append(f"{sb}: {msg}")
        elif fail_closed and msg.endswith("skipped") and os.environ.get("PULSE_REQUIRE_VALIDATORS") == "1":
            errors.append(f"{sb}: validator required but missing")
    if clash.exists():
        ok, msg = validate_mihomo(clash)
        if not ok:
            errors.append(f"{clash}: {msg}")
        elif fail_closed and msg.endswith("skipped") and os.environ.get("PULSE_REQUIRE_VALIDATORS") == "1":
            errors.append(f"{clash}: validator required but missing")
    return errors
