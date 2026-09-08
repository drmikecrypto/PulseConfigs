from __future__ import annotations

import asyncio
import socket
from collections.abc import Iterable

from pulseconfigs.models import ProxyConfig


async def _tcp_ok(host: str, port: int, timeout: float) -> bool:
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        _ = reader
        return True
    except Exception:
        return False


async def probe_l2(
    configs: Iterable[ProxyConfig],
    *,
    timeout: float = 3.0,
    concurrency: int = 200,
) -> list[ProxyConfig]:
    """Mark l2_ok on configs that accept a TCP connection. Dedupes dials by host:port."""
    sem = asyncio.Semaphore(concurrency)
    endpoint_cache: dict[tuple[str, int], bool] = {}
    configs_list = list(configs)

    async def check(cfg: ProxyConfig) -> None:
        key = (cfg.host.lower(), cfg.port)
        if key in endpoint_cache:
            cfg.l2_ok = endpoint_cache[key]
            if not cfg.l2_ok:
                cfg.reject_reason = cfg.reject_reason or "l2_tcp_fail"
            return
        async with sem:
            ok = await _tcp_ok(cfg.host, cfg.port, timeout)
        endpoint_cache[key] = ok
        cfg.l2_ok = ok
        if not ok:
            cfg.reject_reason = "l2_tcp_fail"

    await asyncio.gather(*(check(c) for c in configs_list))
    return configs_list


def probe_l2_sync(configs: Iterable[ProxyConfig], **kwargs: object) -> list[ProxyConfig]:
    return asyncio.run(probe_l2(configs, **kwargs))  # type: ignore[arg-type]


def resolve_host(host: str) -> bool:
    try:
        socket.getaddrinfo(host, None)
        return True
    except OSError:
        return False
