"""Asset inventory loader. src/simulation/config/assets.csv is the single source of truth (M1-01)."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

DEFAULT_ASSETS = Path(__file__).resolve().parents[1] / "config" / "assets.csv"


@dataclass(frozen=True)
class Asset:
    asset_id: str
    hostname: str
    zone: str
    type: str
    ip: str
    protocols: tuple[str, ...]
    notes: str = ""


def load_assets(path: str | Path | None = None) -> list[Asset]:
    with Path(path or DEFAULT_ASSETS).open(newline="", encoding="utf-8") as fh:
        return [
            Asset(
                asset_id=row["asset_id"],
                hostname=row["hostname"],
                zone=row["zone"],
                type=row["type"],
                ip=row["ip"],
                protocols=tuple(p for p in row["protocols"].split(";") if p),
                notes=row.get("notes", ""),
            )
            for row in csv.DictReader(fh)
        ]


def by_type(assets: list[Asset], asset_type: str) -> list[Asset]:
    return [a for a in assets if a.type == asset_type]


def first_of_type(assets: list[Asset], asset_type: str) -> Asset:
    for asset in assets:
        if asset.type == asset_type:
            return asset
    raise LookupError(f"no asset of type {asset_type!r} in the inventory")
