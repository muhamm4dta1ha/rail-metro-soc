"""The three required scenarios (HC-04). A = admin access, B = rogue device, C = service disruption."""

from __future__ import annotations

from railsoc_attacks.scenario import ScenarioBase
from railsoc_attacks.scenarios.a_admin_access import AdminAccessScenario
from railsoc_attacks.scenarios.b_rogue_device import RogueDeviceScenario
from railsoc_attacks.scenarios.c_service_disruption import ServiceDisruptionScenario

REGISTRY: dict[str, type[ScenarioBase]] = {
    AdminAccessScenario.scenario_id: AdminAccessScenario,
    RogueDeviceScenario.scenario_id: RogueDeviceScenario,
    ServiceDisruptionScenario.scenario_id: ServiceDisruptionScenario,
}


def get_scenario(scenario_id: str) -> ScenarioBase:
    try:
        return REGISTRY[scenario_id]()
    except KeyError:
        raise KeyError(f"unknown scenario {scenario_id!r}; expected one of {sorted(REGISTRY)}") from None
