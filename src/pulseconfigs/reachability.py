from __future__ import annotations

import asyncio
import socket
from collections.abc import Iterable

from pulseconfigs.models import ProxyConfig

# UDP-native protocols: TCP connect is not a valid L2 gate.
UDP_PROTOCOLS = frozenset({"hysteria2", "tuic", "wireguard"})


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


async def _udp_reachable(host: str, port: int, timeout: float) -> bool:
    """Best-effort UDP reachability: resolve + send empty datagram (no response required).

    Many UDP proxies do not reply to empty probes; success means the OS accepted
    the send after DNS resolution. Failures (NXDOMAIN, unreachable) mark l2 fail.
    """
    loop = asyncio.get_running_loop()

    def _send() -> bool:
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
        except OSError:
            return False
        if not infos:
            return False
        family, socktype, proto, _, sockaddr = infos[0]
        sock = socket.socket(family, socktype, proto)
        try:
            sock.settimeout(timeout)
            sock.sendto(b"\x00", sockaddr)
            return True
        except OSError:
            return False
        finally:
            sock.close()

    try:
        return await asyncio.wait_for(loop.run_in_executor(None, _send), timeout=timeout + 0.5)
    except Exception:
        return False


async def probe_l2(
    configs: Iterable[ProxyConfig],
    *,
    timeout: float = 3.0,
    concurrency: int = 200,
) -> list[ProxyConfig]:
    """Mark l2_ok. TCP protocols use TCP connect; UDP-native bypass TCP and use UDP dial."""
    sem = asyncio.Semaphore(concurrency)
    endpoint_cache: dict[tuple[str, int, str], bool] = {}
    configs_list = list(configs)

    async def check(cfg: ProxyConfig) -> None:
        mode = "udp" if cfg.protocol in UDP_PROTOCOLS else "tcp"
        key = (cfg.host.lower(), cfg.port, mode)
        if key in endpoint_cache:
            cfg.l2_ok = endpoint_cache[key]
            if not cfg.l2_ok:
                cfg.reject_reason = cfg.reject_reason or f"l2_{mode}_fail"
            return
        async with sem:
            if mode == "udp":
                ok = await _udp_reachable(cfg.host, cfg.port, timeout)
            else:
                ok = await _tcp_ok(cfg.host, cfg.port, timeout)
        endpoint_cache[key] = ok
        cfg.l2_ok = ok
        if not ok:
            cfg.reject_reason = f"l2_{mode}_fail"

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
