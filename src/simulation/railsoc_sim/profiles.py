"""Traffic profiles: how busy the simulated railway is at a given (simulated) time of day."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

DEFAULT_PROFILES = Path(__file__).resolve().parents[1] / "config" / "traffic_profiles.toml"


@dataclass(frozen=True)
class Profile:
    name: str
    telemetry_poll_s: float
    pis_requests_per_min: float
    admin_logins_per_hour: float
    typo_failure_rate: float
    maintenance_writes_per_hour: float
    ssh_sessions_per_hour: float


@dataclass(frozen=True)
class Schedule:
    default: str
    windows: tuple[tuple[float, float, str], ...]  # (start_hour, end_hour, profile name)
    profiles: dict[str, Profile]

    def profile_at(self, moment: datetime) -> Profile:
        hour = moment.hour + moment.minute / 60 + moment.second / 3600
        for start, end, name in self.windows:
            if start <= hour < end:
                return self.profiles[name]
        return self.profiles[self.default]


def load_schedule(path: str | Path | None = None) -> Schedule:
    data = tomllib.loads(Path(path or DEFAULT_PROFILES).read_text(encoding="utf-8"))
    profiles = {
        name: Profile(name=name, **{key: float(value) for key, value in cfg.items()})
        for name, cfg in data["profiles"].items()
    }
    windows = tuple(
        (float(w["start_hour"]), float(w["end_hour"]), w["profile"]) for w in data.get("schedule", [])
    )
    unknown = {name for _, _, name in windows if name not in profiles}
    if unknown:
        raise ValueError(f"schedule references unknown profile(s): {sorted(unknown)}")
    default = data["default_profile"]
    if default not in profiles:
        raise ValueError(f"default_profile {default!r} is not defined")
    return Schedule(default=default, windows=windows, profiles=profiles)
