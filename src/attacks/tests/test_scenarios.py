import re
from pathlib import Path

import pytest

from railsoc_attacks.cli import main
from railsoc_attacks.safety import LabScope, TargetNotAllowed
from railsoc_attacks.scenarios import REGISTRY, get_scenario
from railsoc_common.lab import in_lab

ATTACKS = Path(__file__).resolve().parents[1]
DOCS = {"A": "A_admin_access.md", "B": "B_rogue_device.md", "C": "C_service_disruption.md"}


def test_exactly_the_three_required_scenarios_exist():  # HC-04
    assert sorted(REGISTRY) == ["A", "B", "C"]


@pytest.mark.parametrize("scenario_id", ["A", "B", "C"])
def test_scenario_metadata_is_complete_and_lab_only(scenario_id):
    scenario = get_scenario(scenario_id)
    assert scenario.scenario_id == scenario_id and scenario.title
    assert len(scenario.expected_indicators) >= 3
    assert scenario.techniques and all(re.fullmatch(r"T\d{4}", t) for t in scenario.techniques)
    plan = scenario.plan(dict(scenario.default_params))
    assert plan.attacker_ips and plan.victim_ips
    for ip in (*plan.attacker_ips, *plan.victim_ips):
        assert in_lab(ip)
        LabScope().assert_target_allowed(ip)
    assert (ATTACKS / "docs" / DOCS[scenario_id]).is_file()


def test_cli_lists_scenarios_and_dry_runs_without_ground_truth(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)  # keep any kill-switch lookup away from the repo
    assert main(["list"]) == 0
    assert "Unauthorized administrative access" in capsys.readouterr().out

    gt = tmp_path / "gt.csv"
    args = ["run", "A", "--evidence-dir", str(tmp_path / "ev"), "--ground-truth", str(gt)]
    assert main(args) == 0
    assert "dry_run" in capsys.readouterr().out
    assert not gt.exists()


def test_cli_refuses_non_lab_targets(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(TargetNotAllowed):
        main(["run", "A", "--param", "target_ip=8.8.8.8", "--evidence-dir", str(tmp_path / "ev")])
