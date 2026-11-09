"""Validate events, join ground truth and partition non-overlapping UTC windows."""

from __future__ import annotations

import csv
import json
from collections.abc import Iterable, Sequence
from hashlib import file_digest
from pathlib import Path
from typing import Any

import pandas as pd

from railsoc_common.events import as_utc, validate_event
from railsoc_common.groundtruth import ATTACK, ATTACK_IMPACT, BENIGN, AttackRun, label_event
from railsoc_ml.features import WINDOW_S, events_to_frame, window_features, window_floor

SEVERITY = {BENIGN: 0, ATTACK_IMPACT: 1, ATTACK: 2}
LABEL_COLUMNS = ["label", "run_id", "scenario_id", "is_attack"]
RUN_METADATA = ["attacker_ips", "victim_ips", "victim_assets"]


def known_ips_from_assets(assets_csv: str | Path) -> set[str]:
    """Use all inventory IPs, without filtering by their role or zone."""
    with Path(assets_csv).open(newline="", encoding="utf-8") as fh:
        return {row["ip"] for row in csv.DictReader(fh) if row.get("ip")}


def build_dataset(
    events: Iterable[dict[str, Any]],
    runs: Sequence[AttackRun],
    window_s: int = WINDOW_S,
    known_ips: Iterable[str] | None = None,
) -> pd.DataFrame:
    """One row per UTC window and source, with run information kept outside FEATURES."""
    known = sorted(set(known_ips or ()))
    runs = sorted(runs, key=lambda run: (run.start, run.run_id))
    by_id = {run.run_id: run for run in runs}
    if len(by_id) != len(runs):
        raise ValueError("duplicate ground-truth run IDs")

    records, labels, run_ids, scenarios = [], [], [], []
    attack_runs = [run for run in runs if run.scenario_id != "BASELINE"]
    baselines = [run for run in runs if run.scenario_id == "BASELINE"]
    for event in events:
        validate_event(event)
        ts = as_utc(event["@timestamp"])
        if event["event"]["dataset"] == "ml.alert":
            continue
        label, run_id, scenario = label_event(event, attack_runs)
        if label == BENIGN:
            baseline = next((run for run in baselines if run.start <= ts <= run.end), None)
            if baseline:
                run_id, scenario = baseline.run_id, baseline.scenario_id
        records.append(event)
        labels.append(label)
        run_ids.append(run_id or "")
        scenarios.append(scenario or "")

    frame = events_to_frame(records)
    out = window_features(frame, window_s, known)
    metadata = {"window_s": window_s, "known_ips": known}
    keys = ["window_start", "src_ip"]
    if out.empty:
        out = out.reindex(columns=[*out.columns, *LABEL_COLUMNS, *RUN_METADATA, "campaign_overlap"])
    else:
        frame = frame.assign(
            window_start=window_floor(frame, window_s),
            label=labels,
            run_id=run_ids,
            scenario_id=scenarios,
            severity=[SEVERITY[label] for label in labels],
            tagged=[bool(run_id) for run_id in run_ids],
        )
        strongest = frame.sort_values(
            ["severity", "tagged", "ts", "run_id"],
            ascending=[False, False, True, True],
        ).drop_duplicates(keys)
        out = out.merge(strongest[keys + LABEL_COLUMNS[:3]], on=keys, validate="one_to_one")
        out["is_attack"] = out["label"].eq(ATTACK).astype(int)
        for column in RUN_METADATA:
            out[column] = out["run_id"].map(
                lambda run_id, column=column: (
                    ";".join(getattr(by_id[run_id], column)) if run_id else ""
                )
            )

    # Protect every source in a run's time range, even where it has no event-level label.
    # Run ends are inclusive under the ground-truth contract.
    ranges = []
    overlap = pd.Series(False, index=out.index)
    for run in runs:
        start = pd.Timestamp(run.start).floor(f"{window_s}s")
        end = pd.Timestamp(run.end).floor(f"{window_s}s")
        ranges.append([start.isoformat(), end.isoformat()])
        if run.scenario_id != "BASELINE":
            overlap |= out["window_start"].between(start, end)
    out["campaign_overlap"] = overlap
    out.attrs.update(metadata, run_ranges=ranges, runs=[run.to_row() for run in runs])
    return out


def normal_windows(dataset: pd.DataFrame) -> pd.DataFrame:
    """Exclude campaign-time windows, including victim impact and unrelated traffic."""
    clean = dataset["label"].eq(BENIGN)
    if "campaign_overlap" in dataset:
        clean &= ~dataset["campaign_overlap"]
    elif {"scenario_id", "run_id", "window_start"} <= set(dataset.columns):
        # Old CSVs lack complete intervals. Exclude entire time ranges visible in their labels.
        active = dataset[dataset["scenario_id"].isin(["A", "B", "C"])]
        for _, run in active.groupby("run_id"):
            clean &= ~dataset["window_start"].between(
                run["window_start"].min(), run["window_start"].max()
            )
    return dataset[clean]


def _blocks(dataset: pd.DataFrame) -> list[pd.Timestamp]:
    """Candidate boundaries with all same-time rows and every run kept together."""
    ranges = [
        (pd.Timestamp(start), pd.Timestamp(end))
        for start, end in dataset.attrs.get("run_ranges", [])
    ]
    for _, group in dataset[dataset["run_id"].ne("")].groupby("run_id"):
        ranges.append((group["window_start"].min(), group["window_start"].max()))
    intervals = iter(sorted(ranges))
    upcoming = next(intervals, None)
    protected_until = None
    starts = sorted(dataset["window_start"].unique())
    cuts = starts[:1]
    for start in starts[1:]:
        while upcoming and upcoming[0] < start:
            protected_until = (
                max(protected_until, upcoming[1]) if protected_until is not None else upcoming[1]
            )
            upcoming = next(intervals, None)
        if protected_until is None or protected_until < start:
            cuts.append(start)
    return cuts


def split_windows(
    dataset: pd.DataFrame,
    test_fraction: float = 0.3,
    seed: int = 1,
    *,
    validation_fraction: float = 0.0,
) -> tuple[pd.DataFrame, ...]:
    """Return train/test, or train/validation/test when a validation fraction is supplied.

    Fractions target chronological UTC time. Whole windows and run spans constrain the cuts.
    The seed argument is retained for callers of the former randomized run split.
    """
    if not 0 < test_fraction < 1 or not 0 <= validation_fraction < 1 - test_fraction:
        raise ValueError("split fractions must leave positive training and test shares")
    cuts = _blocks(dataset)
    required = 3 if validation_fraction else 2
    if len(cuts) < required:
        raise ValueError(f"need at least {required} independent time blocks for this split")
    times = dataset["window_start"]
    start = cuts[0]
    span = times.max() - start + pd.Timedelta(seconds=dataset.attrs.get("window_s", WINDOW_S))
    test_cut = min(
        cuts[required - 1 :], key=lambda cut: abs(cut - (start + span * (1 - test_fraction)))
    )
    parts = [dataset[times < test_cut], dataset[times >= test_cut]]
    if validation_fraction:
        target = start + span * (1 - test_fraction - validation_fraction)
        val_cut = min(
            (cut for cut in cuts[1:] if cut < test_cut), key=lambda cut: abs(cut - target)
        )
        parts = [
            dataset[times < val_cut],
            dataset[(times >= val_cut) & (times < test_cut)],
            parts[-1],
        ]
    return tuple(
        part.sort_values(["window_start", "src_ip"]).reset_index(drop=True) for part in parts
    )


def save_dataset(dataset: pd.DataFrame, path: str | Path) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    dataset.to_csv(target, index=False, lineterminator="\n")
    with target.open("rb") as fh:
        checksum = file_digest(fh, "sha256").hexdigest()
    target.with_suffix(".meta.json").write_text(
        json.dumps({**dataset.attrs, "csv_sha256": checksum}, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


def load_dataset(path: str | Path) -> pd.DataFrame:
    source = Path(path)
    dataset = pd.read_csv(source, keep_default_na=False)
    dataset["window_start"] = pd.to_datetime(dataset["window_start"], utc=True, format="ISO8601")
    metadata = source.with_suffix(".meta.json")
    if metadata.exists():
        attrs = json.loads(metadata.read_text(encoding="utf-8"))
        checksum = attrs.pop("csv_sha256", None)
        if checksum is not None:
            with source.open("rb") as fh:
                if file_digest(fh, "sha256").hexdigest() != checksum:
                    raise ValueError("dataset CSV does not match its metadata sidecar")
        dataset.attrs.update(attrs)
    elif "campaign_overlap" in dataset:
        raise ValueError("dataset metadata sidecar is missing; rebuild the dataset")
    return dataset
