from railsoc_common.lab import ZONES, in_lab, zone_of
from railsoc_sim.assets import by_type, first_of_type, load_assets


def test_inventory_is_consistent():
    assets = load_assets()
    assert len({a.asset_id for a in assets}) == len(assets), "asset ids must be unique"
    assert len({a.ip for a in assets}) == len(assets), "ip addresses must be unique"
    for asset in assets:
        assert in_lab(asset.ip), f"{asset.asset_id}: outside the lab address space (HC-18)"
        assert asset.zone in ZONES
        assert zone_of(asset.ip) == asset.zone, f"{asset.asset_id}: ip is not in its zone subnet"


def test_required_asset_types_exist():
    assets = load_assets()
    for kind in (
        "workstation",
        "pis_server",
        "scada_master",
        "jump_host",
        "station_controller",
        "station_display",
        "attacker_host",
        "siem",
    ):
        assert by_type(assets, kind), kind
    assert first_of_type(assets, "pis_server").asset_id == "PIS-01"


def test_station_controllers_are_monitoring_class_only():
    # HC-02: nothing safety-critical (points, signals, interlocking, train protection) is simulated.
    banned = ("point", "signal", "interlock", "train_protection", "balise")
    for asset in load_assets():
        text = f"{asset.asset_id} {asset.type} {asset.notes}".lower()
        assert not any(word in text for word in banned), asset.asset_id
