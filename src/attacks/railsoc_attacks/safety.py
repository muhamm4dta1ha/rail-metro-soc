"""Safety guard: attack tooling may only touch the isolated lab (hard constraints HC-02/HC-03/HC-18).

Every scenario MUST call ``RunContext.guard(ip)`` before sending any traffic to ``ip``.
Hostnames are refused (literal lab IPs only), the scope can be narrowed but never widened beyond
the lab address space, rates and durations are capped, and a kill-switch file aborts a run.
"""

from __future__ import annotations

import ipaddress
import tomllib
from dataclasses import dataclass
from pathlib import Path

from railsoc_common.lab import LAB_CIDR

DEFAULT_SCOPE_FILE = Path(__file__).resolve().parents[1] / "config" / "lab_scope.toml"


class TargetNotAllowed(PermissionError):
    """A scenario tried to touch something outside the isolated lab."""


class KillSwitchEngaged(RuntimeError):
    """The kill-switch file exists: abort immediately."""


@dataclass(frozen=True)
class LabScope:
    allowed: tuple[ipaddress.IPv4Network, ...] = (LAB_CIDR,)
    max_rate_per_s: float = 50.0
    max_duration_s: float = 300.0
    kill_switch_file: Path = Path(".kill_attacks")

    def __post_init__(self) -> None:
        if not self.allowed:
            raise ValueError("scope needs at least one allowed network")
        for net in self.allowed:
            if not net.subnet_of(LAB_CIDR):
                raise ValueError(f"scope {net} is not inside the lab address space {LAB_CIDR}")
        if self.max_rate_per_s <= 0 or self.max_duration_s <= 0:
            raise ValueError("max_rate_per_s and max_duration_s must be positive")

    def assert_target_allowed(self, target: str) -> None:
        """Raise TargetNotAllowed unless `target` is a literal IP inside the allowed lab scope."""
        try:
            addr = ipaddress.ip_address(target)
        except ValueError as exc:
            raise TargetNotAllowed(
                f"{target!r} is not a literal IP address (hostnames are refused)"
            ) from exc
        if not any(addr in net for net in self.allowed):
            allowed = [str(net) for net in self.allowed]
            raise TargetNotAllowed(f"{addr} is outside the allowed lab scope {allowed}")

    def assert_not_killed(self) -> None:
        if self.kill_switch_file.exists():
            raise KillSwitchEngaged(f"kill switch engaged ({self.kill_switch_file})")

    def clamp_rate(self, requested: float) -> float:
        return min(float(requested), self.max_rate_per_s)

    def clamp_duration(self, requested: float) -> float:
        return min(float(requested), self.max_duration_s)


def load_scope(path: str | Path | None = None) -> LabScope:
    data = tomllib.loads(Path(path or DEFAULT_SCOPE_FILE).read_text(encoding="utf-8"))
    return LabScope(
        allowed=tuple(ipaddress.IPv4Network(c) for c in data.get("allowed_cidrs", [str(LAB_CIDR)])),
        max_rate_per_s=float(data.get("max_rate_per_s", 50)),
        max_duration_s=float(data.get("max_duration_s", 300)),
        kill_switch_file=Path(data.get("kill_switch_file", ".kill_attacks")),
    )
