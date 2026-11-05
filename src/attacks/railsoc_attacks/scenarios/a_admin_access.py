"""Scenario A - unauthorized administrative access (task M2-04). STARTER: metadata only.

Docs: src/attacks/docs/A_admin_access.md. Targets: simulated PIS admin portal / maintenance jump host.
"""

from __future__ import annotations

from typing import Any, ClassVar

from railsoc_attacks.scenario import RunContext, ScenarioBase, ScenarioPlan


class AdminAccessScenario(ScenarioBase):
    scenario_id = "A"
    title = "Unauthorized administrative access to the PIS admin portal / maintenance jump host"
    techniques = ("T1110", "T1078")
    expected_indicators = (
        "Burst of failed admin logins (HTTP 401 / sshd failures) from one non-allow-listed source",
        "A successful admin login from that same source shortly after the failures",
        "Admin or configuration action by that session outside the maintenance window",
        "Source address is not in the asset inventory allow-list for administrative access",
    )
    default_params: ClassVar[dict[str, Any]] = {
        "attacker_ip": "10.60.66.10",
        "target_ip": "10.60.20.10",
        "target_asset": "PIS-01",
        "duration_s": 120,
        "rate_per_s": 2,
    }

    def plan(self, params: dict[str, Any]) -> ScenarioPlan:
        return ScenarioPlan(
            attacker_ips=(params["attacker_ip"],),
            victim_ips=(params["target_ip"],),
            victim_assets=(params["target_asset"],),
        )

    def execute(self, ctx: RunContext) -> None:
        raise NotImplementedError(
            "TODO(M2-04): implement against the simulated PIS / jump host only. Call "
            "ctx.guard(ip) before ANY traffic and honour ctx.params['rate_per_s'] and "
            "['duration_s']. See src/attacks/docs/A_admin_access.md and src/attacks/RULES_OF_ENGAGEMENT.md"
        )
