"""Scenario B - anomalous communications from a rogue device (task M2-05). STARTER: metadata only.

Docs: src/attacks/docs/B_rogue_device.md. The rogue device sits in the station zone and is deliberately
NOT in src/simulation/config/assets.csv. Station controllers are monitoring-class (non-safety) only.
"""

from __future__ import annotations

from typing import Any, ClassVar

from railsoc_attacks.scenario import RunContext, ScenarioBase, ScenarioPlan


class RogueDeviceScenario(ScenarioBase):
    scenario_id = "B"
    title = "Anomalous communications from an unknown (rogue) device in the station zone"
    techniques = ("T1046", "T0846", "T0855", "T0856")
    expected_indicators = (
        "A new host (IP/MAC) appears in the station zone that is not in the asset inventory",
        "Connection attempts from that host to many ports/hosts in a short time (discovery pattern)",
        "Control-protocol requests (e.g. Modbus write function codes) from a non-authorised source",
        "MQTT publishes to display topics from an unknown client id / source address",
    )
    default_params: ClassVar[dict[str, Any]] = {
        "attacker_ip": "10.60.30.99",
        "target_ips": ["10.60.30.11", "10.60.20.11"],
        "target_assets": ["ST01-CTL", "MQTT-01"],
        "duration_s": 90,
        "rate_per_s": 5,
    }

    def plan(self, params: dict[str, Any]) -> ScenarioPlan:
        return ScenarioPlan(
            attacker_ips=(params["attacker_ip"],),
            victim_ips=tuple(params["target_ips"]),
            victim_assets=tuple(params["target_assets"]),
        )

    def execute(self, ctx: RunContext) -> None:
        raise NotImplementedError(
            "TODO(M2-05): implement against simulated monitoring-class devices only (never any "
            "safety-related function). Call ctx.guard(ip) before ANY traffic. "
            "See src/attacks/docs/B_rogue_device.md and src/attacks/RULES_OF_ENGAGEMENT.md"
        )
