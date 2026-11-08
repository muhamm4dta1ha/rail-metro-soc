"""Scenario B - anomalous communications from a rogue device (task M2-05). Bounded laboratory runner.

Docs: src/attacks/docs/B_rogue_device.md. The rogue device sits in the station zone and is deliberately
NOT in src/simulation/config/assets.csv. Station controllers are monitoring-class (non-safety) only.
"""

from __future__ import annotations

from typing import Any, ClassVar

from railsoc_attacks.scenario import RunContext, ScenarioBase, ScenarioPlan
from railsoc_attacks.traffic import Budget, modbus_read, validate_params


class RogueDeviceScenario(ScenarioBase):
    scenario_id = "B"
    title = "Anomalous communications from an unknown (rogue) device in the station zone"
    techniques = ("T0846",)
    expected_indicators = (
        "Read-only Modbus function 3 requests from an unapproved source",
        "Repeated reads of monitoring registers 0..3",
        "Higher request frequency than the approved OCC baseline",
    )
    default_params: ClassVar[dict[str, Any]] = {
        "attacker_ip": "10.60.30.99",
        "target_ips": ["10.60.20.22"],
        "target_assets": ["PLC-01"],
        "duration_s": 10,
        "request_count": 8,
        "baseline": False,
        "rate_per_s": 5,
    }

    def plan(self, params: dict[str, Any]) -> ScenarioPlan:
        validate_params(params, params["target_ips"])
        if params["target_ips"] != ["10.60.20.22"]:
            raise ValueError("Scenario B only supports PLC-01 at 10.60.20.22")
        return ScenarioPlan(
            attacker_ips=(params["attacker_ip"],),
            victim_ips=tuple(params["target_ips"]),
            victim_assets=tuple(params["target_assets"]),
        )

    def execute(self, ctx: RunContext) -> None:
        self.plan(ctx.params)
        if ctx.dry_run:
            return
        budget = Budget(ctx)
        for index in range(ctx.params["request_count"]):
            rate = min(1.0, budget.rate) if ctx.params.get("baseline") else budget.rate
            if not budget.slot(ctx.params["target_ips"][0], rate):
                break
            # Original station monitoring registers only; no writes or track occupancy reads.
            result = modbus_read(ctx, budget, index % 4)
            ctx.measurements.append(result)
        budget.finish(ctx.params["target_ips"][0])
