from pathlib import Path

from railsoc_ml.dataset import (
    build_dataset,
    known_ips_from_assets,
    load_dataset,
    save_dataset,
    split_windows,
)

ASSETS = Path(__file__).resolve().parents[2] / "simulation" / "config" / "assets.csv"


def test_labels_come_from_the_ground_truth_runs(stream, h):
    events, runs = stream
    data = build_dataset(events, runs)

    attack = data[data["is_attack"] == 1]
    assert len(attack) == len(runs)  # one window per burst
    assert set(attack["src_ip"]) == {h.ATTACKER}
    assert set(attack["run_id"]) == {run.run_id for run in runs}
    assert (attack["n_failures"] == 60).all()

    impact = data[data["label"] == "attack_impact"]
    assert not impact.empty and (impact["is_attack"] == 0).all()  # normal users hitting the victim

    benign = data[data["label"] == "benign"]
    assert not benign.empty and (benign["run_id"] == "").all()


def test_split_is_grouped_by_run_and_chronological_for_benign_windows(stream):
    events, runs = stream
    data = build_dataset(events, runs)
    train, test = split_windows(data, test_fraction=0.5, seed=3)

    train_runs = set(train["run_id"]) - {""}
    test_runs = set(test["run_id"]) - {""}
    assert train_runs and test_runs and not (train_runs & test_runs)
    assert len(train) + len(test) == len(data)

    benign_train = train[train["run_id"] == ""]
    benign_test = test[test["run_id"] == ""]
    assert benign_train["window_start"].max() <= benign_test["window_start"].min()


def test_split_is_deterministic_for_a_seed(stream):
    events, runs = stream
    data = build_dataset(events, runs)
    first = split_windows(data, 0.5, seed=5)
    second = split_windows(data, 0.5, seed=5)
    assert set(first[1]["run_id"]) == set(second[1]["run_id"])


def test_csv_roundtrip_keeps_labels_and_empty_run_ids(stream, tmp_path):
    events, runs = stream
    data = build_dataset(events, runs)
    path = tmp_path / "processed" / "dataset.csv"
    save_dataset(data, path)
    loaded = load_dataset(path)
    assert len(loaded) == len(data)
    assert int(loaded["is_attack"].sum()) == int(data["is_attack"].sum())
    assert (loaded["run_id"] == "").sum() == (data["run_id"] == "").sum()


def test_known_ips_come_from_the_asset_inventory(h):
    known = known_ips_from_assets(ASSETS)
    assert "10.60.20.10" in known and h.ATTACKER in known
    assert "10.60.30.99" not in known  # the rogue device is deliberately not an asset


def test_no_events_gives_an_empty_dataset():
    assert build_dataset([], []).empty
