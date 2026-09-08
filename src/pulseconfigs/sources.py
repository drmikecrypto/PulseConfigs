from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Source:
    id: str
    url: str
    tier: str  # light | heavy
    enabled: bool = True
    note: str = ""


# Curated public free-config feeds. Attribution: each URL is a public raw subscription.
# PulseConfigs does not claim ownership of upstream nodes.
SOURCES: list[Source] = [
    Source(
        id="mahdibland-sub",
        url="https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
        tier="heavy",
        note="V2RayAggregator merge",
    ),
    Source(
        id="peasoft-list",
        url="https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
        tier="heavy",
    ),
    Source(
        id="freefq-free",
        url="https://raw.githubusercontent.com/freefq/free/master/v2",
        tier="heavy",
    ),
    Source(
        id="Pawdroid-proxy",
        url="https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
        tier="light",
    ),
    Source(
        id="barry-far-v2ray-config",
        url="https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Configs_Sub.txt",
        tier="heavy",
        note="Note lowercase 'config' repo name",
    ),
    Source(
        id="epodonios-sub1",
        url="https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Sub1.txt",
        tier="heavy",
    ),
    Source(
        id="epodonios-sub2",
        url="https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Sub2.txt",
        tier="heavy",
    ),
    Source(
        id="Leon406-vless",
        url="https://raw.githubusercontent.com/Leon406/SubCrawler/main/sub/share/vless",
        tier="light",
    ),
    Source(
        id="Leon406-ss",
        url="https://raw.githubusercontent.com/Leon406/SubCrawler/main/sub/share/ss",
        tier="light",
    ),
    Source(
        id="alirewa-config",
        url="https://raw.githubusercontent.com/Alirewa/V2ray-Configs/main/config.txt",
        tier="heavy",
    ),
    Source(
        id="alirewa-sub1",
        url="https://raw.githubusercontent.com/Alirewa/V2ray-Configs/main/sub1.txt",
        tier="light",
    ),
    Source(
        id="morpheus-lite",
        url="https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/lite.txt",
        tier="light",
    ),
    Source(
        id="morpheus-best",
        url="https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/best.txt",
        tier="heavy",
    ),
]


def active_sources(disabled_ids: set[str] | None = None) -> list[Source]:
    disabled = disabled_ids or set()
    return [s for s in SOURCES if s.enabled and s.id not in disabled]
