from datetime import UTC, datetime

import pytest

from railsoc_attacks.safety import LabScope
from railsoc_attacks.scenario import RunContext, ScenarioBase, ScenarioPlan

T0 = datetime(2026, 1, 5, 9, 0, tzinfo=UTC)


class NoopScenario(ScenarioBase):
    """Harmless scenario used to test the harness: sends no traffic at all."""

    scenario_id = "A"
    title = "noop"
    techniques = ("T1110",)
    expected_indicators = ("none",)
    default_params = {"attacker_ip": "10.60.66.10", "target_ip": "10.60.20.10", "duration_s": 5}

    def plan(self, params):
        return ScenarioPlan((params["attacker_ip"],), (params["target_ip"],), ("PIS-01",))

    def execute(self, ctx: RunContext) -> None:
        ctx.guard(ctx.params["target_ip"])
        ctx.note("noop executed")


@pytest.fixture()
def noop_cls():
    return NoopScenario


@pytest.fixture()
def scope(tmp_path):
    return LabScope(kill_switch_file=tmp_path / ".kill")


@pytest.fixture()
def t0():
    return T0
