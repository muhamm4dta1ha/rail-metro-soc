from railsoc_common.lab import LAB_CIDR, ZONES, in_lab, zone_of


def test_zones_are_inside_the_lab_and_do_not_overlap():
    nets = list(ZONES.values())
    assert all(net.subnet_of(LAB_CIDR) for net in nets)
    for i, first in enumerate(nets):
        for second in nets[i + 1 :]:
            assert not first.overlaps(second)


def test_in_lab_and_zone_of():
    assert in_lab("10.60.20.10")
    assert zone_of("10.60.20.10") == "dmz_ops"
    assert zone_of("10.60.66.10") == "attacker_lab"


def test_anything_outside_the_lab_is_rejected():
    for outside in ("8.8.8.8", "127.0.0.1", "192.168.1.10", "10.61.0.1", "example.com", "::1"):
        assert not in_lab(outside)
    assert zone_of("192.168.1.10") is None
