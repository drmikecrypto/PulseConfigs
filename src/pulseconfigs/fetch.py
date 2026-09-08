from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import httpx

from pulseconfigs.models import ProxyConfig
from pulseconfigs.parse import parse_subscription_text
from pulseconfigs.sources import Source, active_sources


USER_AGENT = "PulseConfigs/0.1 (+https://github.com/PulseConfigs/PulseConfigs)"


@dataclass
class SourceResult:
    source: Source
    ok: bool
    configs: list[ProxyConfig] = field(default_factory=list)
    bytes_len: int = 0
    error: str = ""
    unique_yield: int = 0


async def _fetch_one(client: httpx.AsyncClient, source: Source) -> SourceResult:
    try:
        resp = await client.get(source.url, follow_redirects=True)
        resp.raise_for_status()
        text = resp.text
        try:
            configs = parse_subscription_text(text, source_id=source.id)
        except Exception as parse_exc:  # noqa: BLE001
            return SourceResult(
                source=source,
                ok=False,
                error=f"parse_failed: {parse_exc}",
                bytes_len=len(resp.content),
            )
        return SourceResult(
            source=source,
            ok=True,
            configs=configs,
            bytes_len=len(resp.content),
            unique_yield=len(configs),
        )
    except Exception as exc:  # noqa: BLE001 — isolate per-source failures
        return SourceResult(source=source, ok=False, error=str(exc))


async def fetch_all(
    sources: list[Source] | None = None,
    *,
    timeout: float = 30.0,
    concurrency: int = 12,
) -> list[SourceResult]:
    srcs = sources if sources is not None else active_sources()
    limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency)
    async with httpx.AsyncClient(
        timeout=timeout,
        headers={"User-Agent": USER_AGENT},
        limits=limits,
    ) as client:
        tasks = [_fetch_one(client, s) for s in srcs]
        return list(await asyncio.gather(*tasks))


def fetch_all_sync(
    sources: list[Source] | None = None,
    **kwargs: object,
) -> list[SourceResult]:
    return asyncio.run(fetch_all(sources, **kwargs))  # type: ignore[arg-type]
