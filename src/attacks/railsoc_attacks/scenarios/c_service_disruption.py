"""Scenario C - service disruption (task M2-06). STARTER: metadata only.

Docs: src/attacks/docs/C_service_disruption.md. Controlled, rate-capped and time-boxed degradation of the
SIMULATED passenger-information service inside the isolated lab, with a kill switch.
"""

from __future__ import annotations

from typing import Any, ClassVar

from railsoc_attacks.scenario import RunContext, ScenarioBase, ScenarioPlan


class ServiceDisruptionScenario(ScenarioBase):
    scenario_id = "C"
    title = "Service disruption (availability degradation) of the simulated PIS / MQTT broker"
    techniques = ("T1499", "T0814")
    expected_indicators = (
        "Request/connection rate to the PIS or MQTT broker far above the baseline for that time of day",
        "Rising HTTP 5xx / timeouts and latency on the PIS; station displays show stale data",
        "Broker connection churn or health-check failures",
        "Watchdog / restart events on the affected service (availability category)",
    )
    default_params: ClassVar[dict[str, Any]] = {
        "attacker_ip": "10.60.66.10",
        "target_ip": "10.60.20.10",
        "target_asset": "PIS-01",
        "duration_s": 60,
        "rate_per_s": 20,
    }

    def plan(self, params: dict[str, Any]) -> ScenarioPlan:
        return ScenarioPlan(
            attacker_ips=(params["attacker_ip"],),
            victim_ips=(params["target_ip"],),
            victim_assets=(params["target_asset"],),
        )

    def execute(self, ctx: RunContext) -> None:
        raise NotImplementedError(
            "TODO(M2-06): implement rate-capped and time-boxed against the simulated PIS/broker "
            "only. Call ctx.guard(ip) inside the loop (it checks the kill switch), test the kill "
            "switch first, never run unattended the first time. See src/attacks/docs/C_service_disruption.md"
        )
