"""Scenario C - service disruption (task M2-06). Bounded laboratory runner.

Docs: src/attacks/docs/C_service_disruption.md. Controlled, rate-capped and time-boxed degradation of the
SIMULATED passenger-information service inside the isolated lab, with a kill switch.
"""

from __future__ import annotations

import time
from typing import Any, ClassVar

from railsoc_attacks.scenario import RunContext, ScenarioBase, ScenarioPlan
from railsoc_attacks.traffic import Budget, http_request, validate_params


class ServiceDisruptionScenario(ScenarioBase):
    scenario_id = "C"
    title = "Service disruption (availability degradation) of the simulated PIS / MQTT broker"
    techniques = ("T1499", "T0814")
    expected_indicators = (
        "Increased GET /api/arrivals request rate compared with baseline",
        "Measured latency, HTTP errors and timeouts, if observed",
        "Recovery probe results after the bounded test interval",
    )
    default_params: ClassVar[dict[str, Any]] = {
        "attacker_ip": "10.60.66.10",
        "target_ip": "10.60.20.10",
        "target_asset": "PIS-01",
        "duration_s": 12,
        "baseline": False,
        "rate_per_s": 20,
    }

    def plan(self, params: dict[str, Any]) -> ScenarioPlan:
        validate_params(params, [params["target_ip"]])
        if params["target_ip"] != "10.60.20.10":
            raise ValueError("Scenario C only supports the PIS at 10.60.20.10")
        return ScenarioPlan(
            attacker_ips=(params["attacker_ip"],),
            victim_ips=(params["target_ip"],),
            victim_assets=(params["target_asset"],),
        )

    def execute(self, ctx: RunContext) -> None:
        self.plan(ctx.params)
        if ctx.dry_run:
            return
        budget = Budget(ctx)
        # A single deadline includes all three phases. Sequential calls; no service changes.
        for phase, fraction, rate in (("baseline", 0.25, 1), ("test", 0.75, budget.rate),
                                      ("recovery", 1.0, 1)):
            phase_end = budget.started + budget.duration * fraction
            started = time.monotonic()
            observations = []
            while time.monotonic() < phase_end:
                requested_rate = 1 if ctx.params.get("baseline") else rate
                if not budget.slot(ctx.params["target_ip"], requested_rate, until=phase_end):
                    break
                if time.monotonic() >= phase_end:
                    break
                observations.append(http_request(ctx, budget, "/api/arrivals"))
            elapsed = time.monotonic() - started
            successes = sum(x["status"] == 200 for x in observations)
            ctx.measurements.append({
                "phase": phase, "requests": len(observations), "elapsed_s": elapsed,
                "rate_per_s": len(observations) / elapsed if elapsed else 0,
                "successes": successes, "failures": len(observations) - successes,
                "timeouts": sum(x["error"] in ("TimeoutError", "Timeout") for x in observations),
                "mean_latency_ms": (sum(x["latency_ms"] for x in observations) / len(observations)
                                    if observations else None),
            })
        ctx.note("Request-rate test only; availability degradation must be established from measurements")
