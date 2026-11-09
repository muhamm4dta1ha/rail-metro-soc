"""Inference (task M4-10): score events window by window and emit `ml.alert` events.

The alerts are ordinary contract events (dataset `ml.alert`), so Module 3 ingests them into the SIEM
next to rule alerts (rule ids 100400-100499) and railsoc_detection.evaluate scores them too.
Incremental scoring consumes timestamp-ordered input and closes each window once.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

from railsoc_common.events import (
    as_utc,
    make_event,
    read_events,
    utc_iso,
    validate_event,
    write_events,
)
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
    windows = window_features(events_to_frame(_input_events(events)), window_s, known_ips)
    return list(window_alerts(windows, detector, window_s=window_s, host_name=host_name))


def _input_events(events: Iterable[dict[str, Any]]) -> Iterator[dict[str, Any]]:
    for event in events:
        validate_event(event)
        as_utc(event["@timestamp"])
        if event["event"]["dataset"] != "ml.alert":
            yield event


def window_alerts(windows, detector, *, window_s: int, host_name: str = "ml-detector"):
    """Use the same schema events for inference and held-out evaluation."""
    if windows.empty:
        return
    if detector.threshold is None:
        raise ValueError("score requires a calibrated model")
    scores = detector.score(windows)
    flagged = scores > detector.threshold
    for (_, row), score in zip(windows.loc[flagged].iterrows(), scores[flagged], strict=True):
        start = row["window_start"].to_pydatetime()
        end = start + timedelta(seconds=window_s)
        source_ip = row["src_ip"]
        yield make_event(
            "ml.alert",
            "intrusion_detection",
            "anomaly_detected",
            "unknown",
            ts=end,
            host={"name": host_name},
            source={"ip": source_ip} if source_ip else None,
            ml={
                "model": detector.name,
                "score": float(score),
                "threshold": float(detector.threshold),
                "window_start": utc_iso(start),
                "window_end": utc_iso(end),
                "top_features": detector.explain(row),
            },
            message=f"anomalous activity from {source_ip or 'n/a'} in a {window_s}s window",
        )


def score_stream(
    events: Iterable[dict[str, Any]],
    detector,
    *,
    window_s: int = WINDOW_S,
    known_ips: Iterable[str] | None = None,
    max_window_events: int = 100_000,
) -> Iterator[dict[str, Any]]:
    """Incrementally score one event-time bin at a time, including the last bin at EOF."""
    if window_s <= 0 or max_window_events <= 0:
        raise ValueError("window_s and max_window_events must be positive")
    origin = datetime(1970, 1, 1, tzinfo=UTC)
    interval = timedelta(seconds=window_s)
    known = set(known_ips or ())
    previous = start = None
    pending = []
    for event in _input_events(events):
        ts = as_utc(event["@timestamp"])
        if previous is not None and ts < previous:
            raise ValueError("streaming input must be in nondecreasing timestamp order")
        previous = ts
        current = (ts - origin) // interval
        if pending and current != start:
            windows = window_features(events_to_frame(pending), window_s, known)
            yield from window_alerts(windows, detector, window_s=window_s)
            pending.clear()
        if len(pending) >= max_window_events:
            raise ValueError(f"window exceeds the limit of {max_window_events} events")
        pending.append(event)
        start = current
    if pending:
        windows = window_features(events_to_frame(pending), window_s, known)
        yield from window_alerts(windows, detector, window_s=window_s)


def score_file(
    events_path: str | Path,
    detector,
    out_path: str | Path,
    *,
    window_s: int = WINDOW_S,
    known_ips: Iterable[str] | None = None,
    streaming: bool = False,
    max_window_events: int = 100_000,
) -> int:
    """Score a JSON Lines event file and write the alerts as JSON Lines. Returns the alert count."""
    events = read_events(events_path)
    if streaming:
        alerts = score_stream(
            events,
            detector,
            window_s=window_s,
            known_ips=known_ips,
            max_window_events=max_window_events,
        )
    else:
        alerts = score_events(events, detector, window_s=window_s, known_ips=known_ips)
    target = Path(out_path)
    if target.resolve() == Path(events_path).resolve():
        raise ValueError("alert output must differ from the input log")
    target.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile(dir=target.parent, suffix=".tmp", delete=False) as temporary:
        pending_path = Path(temporary.name)
    try:
        count = write_events(pending_path, alerts)
        pending_path.replace(target)
    finally:
        pending_path.unlink(missing_ok=True)
    return count
