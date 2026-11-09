"""Feature extraction: contract events -> per-source time-window features (tasks M4-04 / M4-05).

Only fields that exist in the event schema are used - never `message` text and never labels
(HC-19). One row = one (time window, source IP). See src/ml/reports/feature_catalogue.md for definitions.
"""

from __future__ import annotations

from collections.abc import Iterable
from math import isfinite
from typing import Any

import pandas as pd

WINDOW_S = 10
MODBUS_READ_CODES = {1, 2, 3, 4}
MODBUS_WRITE_CODES = {5, 6, 15, 16}
MODBUS_CODES = sorted(MODBUS_READ_CODES | MODBUS_WRITE_CODES)
TELEMETRY = {
    "station_temp_c": "C",
    "feeder_voltage_v": "V",
    "platform_occupancy_pct": "%",
    "lift_available": "bool",
}
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
    "n_auth_failures",
    "auth_failure_ratio",
    "http_requests_per_s",
    "mean_http_latency_ms",
    "n_http_latency_samples",
    "n_modbus_read",
    *[f"modbus_fc_{code}_ratio" for code in MODBUS_CODES],
    "modbus_fc_other_ratio",
    "n_mqtt_connect",
    "n_mqtt_topics",
    "network_bytes",
    "network_packets",
    "n_metric_samples",
    *[f"{name}_{stat}" for name in TELEMETRY for stat in ("mean", "range")],
]
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
    "category",
    "http_request",
    "http_latency",
    "mqtt_topic",
    "network_bytes",
    "network_packets",
    "metric_name",
    "metric_unit",
    "metric_value",
]


def events_to_frame(events: Iterable[dict[str, Any]]) -> pd.DataFrame:
    """Flatten the schema fields the features need into one row per event."""
    rows = []
    for ev in events:
        info = ev["event"]
        network = ev.get("network", {})
        http = ev.get("http", {})
        response = http.get("response", {})
        metric = ev.get("metric", {})
        for value in (response.get("latency_ms"), metric.get("value")):
            if value is not None and not isfinite(value):
                raise ValueError("event numeric measurements must be finite")
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
                "http_status": response.get("status_code", 0),
                "modbus_fc": ev.get("modbus", {}).get("function_code", 0),
                "protocol": network.get("protocol", ""),
                "category": info["category"],
                "http_request": bool(http.get("request", {}).get("method")),
                "http_latency": response.get("latency_ms"),
                "mqtt_topic": ev.get("mqtt", {}).get("topic") or None,
                "network_bytes": network.get("bytes", 0),
                "network_packets": network.get("packets", 0),
                "metric_name": metric.get("name", ""),
                "metric_unit": metric.get("unit", ""),
                "metric_value": metric.get("value"),
            }
        )
    frame = pd.DataFrame(rows, columns=FRAME_COLUMNS)
    frame["ts"] = pd.to_datetime(frame["ts"], utc=True, format="ISO8601")
    return frame


def window_floor(frame: pd.DataFrame, window_s: int = WINDOW_S) -> pd.Series:
    """Start of the time window each event falls into."""
    if not isinstance(window_s, int) or window_s <= 0:
        raise ValueError("window_s must be a positive integer")
    return frame["ts"].dt.floor(f"{window_s}s")


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
    starts = window_floor(frame, window_s)
    if frame.empty:
        return pd.DataFrame(columns=columns)

    prepared = frame.assign(
        window_start=starts,
        is_auth=frame["category"].eq("authentication"),
        is_auth_failure=frame["category"].eq("authentication") & frame["outcome"].eq("failure"),
        is_http=frame["http_request"]
        | frame["http_status"].gt(0)
        | (frame["protocol"].eq("http") & frame["action"].eq("request")),
        http_latency=pd.to_numeric(frame["http_latency"]),
        is_mb_read=frame["modbus_fc"].isin(MODBUS_READ_CODES),
        has_fc=frame["modbus_fc"].gt(0),
        is_connect=frame["protocol"].eq("mqtt") & frame["action"].eq("connect"),
        is_failure=(frame["outcome"] == "failure").astype(int),
        is_4xx=frame["http_status"].between(400, 499).astype(int),
        is_5xx=frame["http_status"].between(500, 599).astype(int),
        is_mb_write=frame["modbus_fc"].isin(MODBUS_WRITE_CODES).astype(int),
        is_publish=((frame["protocol"] == "mqtt") & (frame["action"] == "publish")).astype(int),
        dst_ip_known=frame["dst_ip"].where(frame["dst_ip"] != ""),
        dst_port_known=frame["dst_port"].where(frame["dst_port"] > 0),
    )
    aggregates = {}
    for code in MODBUS_CODES:
        name = f"modbus_fc_{code}_ratio"
        prepared[name] = prepared["modbus_fc"].eq(code).where(prepared["has_fc"])
        aggregates[name] = (name, "mean")
    prepared["modbus_fc_other_ratio"] = (~prepared["modbus_fc"].isin(MODBUS_CODES)).where(
        prepared["has_fc"]
    )
    aggregates["modbus_fc_other_ratio"] = ("modbus_fc_other_ratio", "mean")
    metric_values = pd.to_numeric(prepared["metric_value"])
    for name, unit in TELEMETRY.items():
        prepared[name] = metric_values.where(
            prepared["metric_name"].eq(name) & prepared["metric_unit"].eq(unit)
        )
        for stat in ("mean", "min", "max"):
            aggregates[f"{name}_{stat}"] = (name, stat)
    out = (
        prepared.sort_values("ts", kind="stable")
        .groupby(["window_start", "src_ip"], sort=True)
        .agg(
            n_events=("ts", "size"),
            n_failures=("is_failure", "sum"),
            n_unique_dst_ip=("dst_ip_known", "nunique"),
            n_unique_dst_port=("dst_port_known", "nunique"),
            n_http_4xx=("is_4xx", "sum"),
            n_http_5xx=("is_5xx", "sum"),
            n_modbus_write=("is_mb_write", "sum"),
            n_mqtt_publish=("is_publish", "sum"),
            n_mqtt_connect=("is_connect", "sum"),
            n_mqtt_topics=("mqtt_topic", "nunique"),
            n_auth=("is_auth", "sum"),
            n_auth_failures=("is_auth_failure", "sum"),
            n_http=("is_http", "sum"),
            mean_http_latency_ms=("http_latency", "mean"),
            n_http_latency_samples=("http_latency", "count"),
            n_modbus_read=("is_mb_read", "sum"),
            network_bytes=("network_bytes", "sum"),
            network_packets=("network_packets", "sum"),
            n_metric_samples=("metric_value", "count"),
            **aggregates,
        )
        .reset_index()
    )
    out["failure_ratio"] = out["n_failures"] / out["n_events"]
    out["auth_failure_ratio"] = out["n_auth_failures"] / out["n_auth"].where(out["n_auth"] > 0)
    out["http_requests_per_s"] = out["n_http"] / window_s
    for name in TELEMETRY:
        out[f"{name}_range"] = out[f"{name}_max"] - out[f"{name}_min"]
    known = set(known_ips or [])
    if known:
        out["n_new_source"] = ((out["src_ip"] != "") & ~out["src_ip"].isin(known)).astype(int)
    else:
        out["n_new_source"] = 0
    out[FEATURES] = out[FEATURES].apply(pd.to_numeric).fillna(0)
    return out[columns]
