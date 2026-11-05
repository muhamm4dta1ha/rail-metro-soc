"""Dataset building: events + ground truth -> labelled windows (tasks M4-04 / M4-09).

Labels come ONLY from the ground-truth runs through railsoc_common.groundtruth.label_event.
Splits are by RUN (attack windows) and by TIME (benign windows), never by random rows, so a model
cannot memorise one run (leakage rule, PLAN.md section 12).
"""

from __future__ import annotations

import csv
import random
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

import pandas as pd

from railsoc_common.groundtruth import ATTACK, ATTACK_IMPACT, BENIGN, AttackRun, label_event
from railsoc_ml.features import WINDOW_S, events_to_frame, window_features, window_floor

SEVERITY = {BENIGN: 0, ATTACK_IMPACT: 1, ATTACK: 2}
LABEL_COLUMNS = ["label", "run_id", "scenario_id", "is_attack"]


def known_ips_from_assets(assets_csv: str | Path) -> set[str]:
    """IPs of the asset inventory (src/simulation/config/assets.csv) = the known-source allow-list."""
    with Path(assets_csv).open(newline="", encoding="utf-8") as fh:
        return {row["ip"] for row in csv.DictReader(fh) if row.get("ip")}


def build_dataset(
    events: Iterable[dict[str, Any]],
    runs: Sequence[AttackRun],
    window_s: int = WINDOW_S,
    known_ips: Iterable[str] | None = None,
) -> pd.DataFrame:
    """One row per (window, source IP): features + label (benign / attack_impact / attack)."""
    events = list(events)
    frame = events_to_frame(events)
    features = window_features(frame, window_s, known_ips)
    if features.empty:
        return features.assign(label=[], run_id=[], scenario_id=[], is_attack=[])

    labels = [label_event(event, runs) for event in events]
    frame = frame.assign(
        label=[x.label for x in labels],
        run_id=[x.run_id or "" for x in labels],
        scenario_id=[x.scenario_id or "" for x in labels],
        window_start=window_floor(frame, window_s),
    )
    frame["severity"] = frame["label"].map(SEVERITY)
    strongest = frame.loc[
        frame.groupby(["window_start", "src_ip"])["severity"].idxmax(),
        ["window_start", "src_ip", "label", "run_id", "scenario_id"],
    ]
    out = features.merge(strongest, on=["window_start", "src_ip"], how="left")
    out["is_attack"] = (out["label"] == ATTACK).astype(int)
    return out


def split_windows(
    dataset: pd.DataFrame, test_fraction: float = 0.3, seed: int = 1
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Run-grouped split for attack windows, chronological split for benign windows.

    Needs at least two attack runs to put one in the test set.
    """
    benign = dataset[dataset["run_id"] == ""].sort_values("window_start")
    cut = int(len(benign) * (1 - test_fraction))
    attack = dataset[dataset["run_id"] != ""]

    run_ids = sorted(attack["run_id"].unique())
    random.Random(seed).shuffle(run_ids)
    n_test = max(1, round(len(run_ids) * test_fraction)) if len(run_ids) > 1 else 0
    test_runs = set(run_ids[:n_test])

    train = pd.concat([benign.iloc[:cut], attack[~attack["run_id"].isin(test_runs)]])
    test = pd.concat([benign.iloc[cut:], attack[attack["run_id"].isin(test_runs)]])
    return train.reset_index(drop=True), test.reset_index(drop=True)


def save_dataset(dataset: pd.DataFrame, path: str | Path) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    dataset.to_csv(target, index=False)


def load_dataset(path: str | Path) -> pd.DataFrame:
    dataset = pd.read_csv(path)
    dataset["window_start"] = pd.to_datetime(dataset["window_start"], utc=True)
    for column in ("src_ip", "label", "run_id", "scenario_id"):
        dataset[column] = dataset[column].fillna("")
    return dataset
