"""Inference (task M4-10): score events window by window and emit `ml.alert` events.

The alerts are ordinary contract events (dataset `ml.alert`), so Module 3 ingests them into the SIEM
next to rule alerts (rule ids 100400-100499) and railsoc_detection.evaluate scores them too.
Starter = batch scoring of a file; M4-10 adds streaming (tail the live log / flow files).
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import timedelta
from pathlib import Path
from typing import Any

from railsoc_common.events import make_event, read_events, utc_iso, write_events
from railsoc_ml.features import WINDOW_S, events_to_frame, window_features


def score_events(
    events: Iterable[dict[str, Any]],
    detector,
    *,
    window_s: int = WINDOW_S,
    known_ips: Iterable[str] | None = None,
    host_name: str = "ml-detector",
) -> list[dict[str, Any]]:
    """Return one `ml.alert` event per (window, source) whose score exceeds the threshold."""
    windows = window_features(events_to_frame(events), window_s, known_ips)
    if windows.empty:
        return []
    alerts: list[dict[str, Any]] = []
    for (_, row), score in zip(windows.iterrows(), detector.score(windows), strict=True):
        if score <= detector.threshold:
            continue
        start = row["window_start"].to_pydatetime()
        end = start + timedelta(seconds=window_s)
        source_ip = row["src_ip"]
        alerts.append(
            make_event(
                "ml.alert",
                "intrusion_detection",
                "anomaly_detected",
                "unknown",
                ts=end,
                host={"name": host_name},
                source={"ip": source_ip} if source_ip else None,
                ml={
                    "model": detector.name,
                    "score": round(float(score), 4),
                    "threshold": round(float(detector.threshold), 4),
                    "window_start": utc_iso(start),
                    "window_end": utc_iso(end),
                    "top_features": detector.explain(row),
                },
                message=f"anomalous activity from {source_ip or 'n/a'} in a {window_s}s window",
            )
        )
    return alerts


def score_file(
    events_path: str | Path,
    detector,
    out_path: str | Path,
    *,
    window_s: int = WINDOW_S,
    known_ips: Iterable[str] | None = None,
) -> int:
    """Score a JSON Lines event file and write the alerts as JSON Lines. Returns the alert count."""
    alerts = score_events(
        read_events(events_path), detector, window_s=window_s, known_ips=known_ips
    )
    return write_events(out_path, alerts)
