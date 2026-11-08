"""Scenario A - unauthorized administrative access (task M2-04). Bounded laboratory runner.

Docs: src/attacks/docs/A_admin_access.md. Targets: simulated PIS admin portal / maintenance jump host.
"""

from __future__ import annotations

import os
from typing import Any, ClassVar

from railsoc_attacks.scenario import RunContext, ScenarioBase, ScenarioPlan
from railsoc_attacks.traffic import Budget, http_request, validate_params


class AdminAccessScenario(ScenarioBase):
    scenario_id = "A"
    title = "Unauthorized administrative access to the PIS admin portal / maintenance jump host"
    techniques = ("T1110", "T1078")
    expected_indicators = (
        "Burst of failed admin logins (HTTP 401 / sshd failures) from one non-allow-listed source",
        "A successful admin login from that same source shortly after the failures",
        "HTTP status codes and client response latency",
        "Source address is not in the asset inventory allow-list for administrative access",
    )
    default_params: ClassVar[dict[str, Any]] = {
        "attacker_ip": "10.60.66.10",
        "target_ip": "10.60.20.10",
        "target_asset": "PIS-01",
        "duration_s": 15,
        "request_count": 6,
        "baseline": False,
        "rate_per_s": 2,
    }

    def plan(self, params: dict[str, Any]) -> ScenarioPlan:
        validate_params(params, [params["target_ip"]])
        if params["target_ip"] != "10.60.20.10":
            raise ValueError("Scenario A only supports the PIS at 10.60.20.10")
        return ScenarioPlan(
            attacker_ips=(params["attacker_ip"],),
            victim_ips=(params["target_ip"],),
            victim_assets=(params["target_asset"],),
        )

    def execute(self, ctx: RunContext) -> None:
        self.plan(ctx.params)
        if ctx.dry_run:
            return
        # The approved synthetic account is injected locally, never recorded in params.
        username = os.environ.get("M2_PIS_USER")
        password = os.environ.get("M2_PIS_PASSWORD")
        if not username or not password:
            raise ValueError("Set M2_PIS_USER and M2_PIS_PASSWORD for a synthetic PIS account")
        budget = Budget(ctx)
        count = 1 if ctx.params.get("baseline") else ctx.params["request_count"]
        for index in range(count):
            if not budget.slot(ctx.params["target_ip"]):
                ctx.note("Duration cap reached before sequence finished")
                break
            valid = index == count - 1
            result = http_request(ctx, budget, "/api/login", {
                "username": username if valid else "m2_invalid_account",
                "password": password if valid else "invalid_synthetic_value",
            })
            ctx.measurements.append({**result, "expected_status": 200 if valid else 401})
        budget.finish(ctx.params["target_ip"])
        if not ctx.measurements or any(x["status"] != x["expected_status"] for x in ctx.measurements):
            ctx.note("Observed authentication sequence differs from expected 401 then 200")
