"""Feature extraction: contract events -> per-source time-window features (tasks M4-04 / M4-05).

Only fields that exist in the event schema are used - never `message` text and never labels
(HC-19). One row = one (time window, source IP). This is the starter set; Module 4 extends it
(M4-05) and documents every feature in src/ml/reports/feature_catalogue.md.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import pandas as pd

WINDOW_S = 10
FEATURES = [
    "n_events",
    "n_failures",
    "failure_ratio",
    "n_unique_dst_ip",
    "n_unique_dst_port",
    "n_http_4xx",
    "n_http_5xx",
    "n_modbus_write",
    "n_mqtt_publish",
    "n_new_source",
]
MODBUS_WRITE_CODES = {5, 6, 15, 16}
FRAME_COLUMNS = [
    "ts",
    "dataset",
    "action",
    "outcome",
    "src_ip",
    "dst_ip",
    "dst_port",
    "http_status",
    "modbus_fc",
    "protocol",
]


def events_to_frame(events: Iterable[dict[str, Any]]) -> pd.DataFrame:
    """Flatten the schema fields the features need into one row per event."""
    rows = []
    for ev in events:
        info = ev["event"]
        src = ev.get("source", {})
        dst = ev.get("destination", {})
        rows.append(
            {
                "ts": ev["@timestamp"],
                "dataset": info["dataset"],
                "action": info["action"],
                "outcome": info["outcome"],
                "src_ip": src.get("ip", ""),
                "dst_ip": dst.get("ip", ""),
                "dst_port": dst.get("port", 0),
                "http_status": ev.get("http", {}).get("response", {}).get("status_code", 0),
                "modbus_fc": ev.get("modbus", {}).get("function_code", 0),
                "protocol": ev.get("network", {}).get("protocol", ""),
            }
        )
    frame = pd.DataFrame(rows, columns=FRAME_COLUMNS)
    frame["ts"] = pd.to_datetime(frame["ts"], utc=True, format="ISO8601")
    return frame


def window_floor(frame: pd.DataFrame, window_s: int = WINDOW_S) -> pd.Series:
    """Start of the time window each event falls into."""
    return frame["ts"].dt.floor(f"{int(window_s)}s")


def window_features(
    frame: pd.DataFrame,
    window_s: int = WINDOW_S,
    known_ips: Iterable[str] | None = None,
) -> pd.DataFrame:
    """Aggregate events into (window_start, src_ip) rows with the FEATURES columns.

    `known_ips` is the allow-list of known sources (e.g. the asset inventory); when it is empty or
    None the `n_new_source` feature is 0 for every row.
    """
    columns = ["window_start", "src_ip", *FEATURES]
    if frame.empty:
        return pd.DataFrame(columns=columns)

    prepared = frame.assign(
        window_start=window_floor(frame, window_s),
        is_failure=(frame["outcome"] == "failure").astype(int),
        is_4xx=frame["http_status"].between(400, 499).astype(int),
        is_5xx=frame["http_status"].between(500, 599).astype(int),
        is_mb_write=frame["modbus_fc"].isin(MODBUS_WRITE_CODES).astype(int),
        is_publish=((frame["protocol"] == "mqtt") & (frame["action"] == "publish")).astype(int),
        dst_ip_known=frame["dst_ip"].where(frame["dst_ip"] != ""),
        dst_port_known=frame["dst_port"].where(frame["dst_port"] > 0),
    )
    out = (
        prepared.groupby(["window_start", "src_ip"], sort=True)
        .agg(
            n_events=("ts", "size"),
            n_failures=("is_failure", "sum"),
            n_unique_dst_ip=("dst_ip_known", "nunique"),
            n_unique_dst_port=("dst_port_known", "nunique"),
            n_http_4xx=("is_4xx", "sum"),
            n_http_5xx=("is_5xx", "sum"),
            n_modbus_write=("is_mb_write", "sum"),
            n_mqtt_publish=("is_publish", "sum"),
        )
        .reset_index()
    )
    out["failure_ratio"] = out["n_failures"] / out["n_events"]
    known = set(known_ips or [])
    if known:
        out["n_new_source"] = ((out["src_ip"] != "") & ~out["src_ip"].isin(known)).astype(int)
    else:
        out["n_new_source"] = 0
    return out[columns]
