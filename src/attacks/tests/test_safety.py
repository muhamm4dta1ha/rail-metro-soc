import ipaddress

import pytest

from railsoc_attacks.safety import KillSwitchEngaged, LabScope, TargetNotAllowed, load_scope


def test_lab_addresses_are_allowed():
    scope = LabScope()
    scope.assert_target_allowed("10.60.20.10")
    scope.assert_target_allowed("10.60.66.10")


@pytest.mark.parametrize(
    "target",
    [
        "8.8.8.8",
        "127.0.0.1",
        "192.168.1.10",
        "10.61.0.1",
        "0.0.0.0",
        "255.255.255.255",
        "pis-01",
        "example.com",
        "::1",
        "",
    ],
)
def test_everything_outside_the_lab_is_refused(target):
    with pytest.raises(TargetNotAllowed):
        LabScope().assert_target_allowed(target)


def test_scope_can_be_narrowed_but_never_widened():
    narrow = LabScope(allowed=(ipaddress.IPv4Network("10.60.20.0/24"),))
    narrow.assert_target_allowed("10.60.20.10")
    with pytest.raises(TargetNotAllowed):
        narrow.assert_target_allowed("10.60.30.11")
    for wider in ("10.0.0.0/8", "192.168.0.0/16", "0.0.0.0/0"):
        with pytest.raises(ValueError, match="lab address space"):
            LabScope(allowed=(ipaddress.IPv4Network(wider),))


def test_caps_are_clamped():
    scope = LabScope(max_rate_per_s=5, max_duration_s=30)
    assert scope.clamp_rate(1000) == 5
    assert scope.clamp_rate(2) == 2
    assert scope.clamp_duration(1000) == 30
    with pytest.raises(ValueError):
        LabScope(max_rate_per_s=0)


def test_kill_switch(tmp_path):
    kill = tmp_path / ".kill"
    scope = LabScope(kill_switch_file=kill)
    scope.assert_not_killed()
    kill.write_text("stop")
    with pytest.raises(KillSwitchEngaged):
        scope.assert_not_killed()


def test_the_shipped_scope_file_is_valid_and_lab_only():
    scope = load_scope()
    scope.assert_target_allowed("10.60.66.10")
    with pytest.raises(TargetNotAllowed):
        scope.assert_target_allowed("203.0.113.5")
