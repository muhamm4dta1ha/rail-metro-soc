"""Scenario framework: every attack scenario implements ScenarioBase and runs via the recorder."""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any, ClassVar

from railsoc_attacks.safety import LabScope


@dataclass(frozen=True)
class ScenarioPlan:
    """Who attacks whom (used for the ground-truth row). All addresses must be lab IPs."""

    attacker_ips: tuple[str, ...]
    victim_ips: tuple[str, ...]
    victim_assets: tuple[str, ...] = ()


@dataclass
class RunContext:
    run_id: str
    scope: LabScope
    params: dict[str, Any]
    dry_run: bool
    actions: list[str] = field(default_factory=list)

    def guard(self, target_ip: str) -> None:
        """MUST be called before sending ANY traffic to `target_ip` (and inside long loops)."""
        self.scope.assert_not_killed()
        self.scope.assert_target_allowed(target_ip)

    def note(self, message: str) -> None:
        """Record a human-readable action in the run manifest."""
        self.actions.append(message)


class ScenarioBase(abc.ABC):
    scenario_id: ClassVar[str]
    title: ClassVar[str]
    techniques: ClassVar[tuple[str, ...]]  # MITRE ATT&CK ids - verify on attack.mitre.org
    expected_indicators: ClassVar[tuple[str, ...]]
    default_params: ClassVar[dict[str, Any]]

    @abc.abstractmethod
    def plan(self, params: dict[str, Any]) -> ScenarioPlan:
        """Return attacker/victim addresses for these params (no traffic is sent here)."""

    @abc.abstractmethod
    def execute(self, ctx: RunContext) -> None:
        """Run the scenario. Call ctx.guard(ip) before ANY traffic; honour rate/duration caps."""
