from datetime import timedelta

from railsoc_common.events import make_event
from railsoc_ml.features import FEATURES, events_to_frame, window_features


def test_counts_for_one_window_and_source(h):
    events = [
        h.login(h.T0, h.ATTACKER, ok=False),
        h.login(h.T0 + timedelta(seconds=1), h.ATTACKER, ok=False),
        h.request(h.T0 + timedelta(seconds=2), h.ATTACKER, status=503),
    ]
    (row,) = window_features(events_to_frame(events)).to_dict("records")
    assert row["src_ip"] == h.ATTACKER
    assert row["n_events"] == 3 and row["n_failures"] == 3
    assert row["failure_ratio"] == 1.0
    assert row["n_http_4xx"] == 2 and row["n_http_5xx"] == 1
    assert row["n_unique_dst_ip"] == 1 and row["n_unique_dst_port"] == 1
    assert row["n_modbus_write"] == 0 and row["n_mqtt_publish"] == 0


def test_events_are_split_into_aligned_windows_and_sources(h):
    events = [
        h.request(h.T0 + timedelta(seconds=9), "10.60.10.21"),
        h.request(h.T0 + timedelta(seconds=11), "10.60.10.21"),
        h.request(h.T0 + timedelta(seconds=11), "10.60.10.22"),
    ]
    windows = window_features(events_to_frame(events), window_s=10)
    assert len(windows) == 3
    assert windows["window_start"].nunique() == 2


def test_modbus_writes_and_mqtt_publishes_are_counted(h):
    write = make_event(
        "scada.command",
        "configuration",
        "write_register",
        "success",
        ts=h.T0,
        host={"name": "st01-ctl"},
        source={"ip": "10.60.30.99"},
        destination={"ip": "10.60.30.11", "port": 502},
        network={"protocol": "modbus", "transport": "tcp"},
        modbus={"function_code": 6, "unit_id": 1, "address": 10},
    )
    publish = make_event(
        "mqtt.broker",
        "network",
        "publish",
        "success",
        ts=h.T0,
        host={"name": "mqtt-01"},
        source={"ip": "10.60.30.99"},
        destination={"ip": "10.60.20.11", "port": 1883},
        network={"protocol": "mqtt", "transport": "tcp"},
        mqtt={"topic": "displays/st01", "client_id": "unknown"},
    )
    (row,) = window_features(events_to_frame([write, publish])).to_dict("records")
    assert row["n_modbus_write"] == 1 and row["n_mqtt_publish"] == 1
    assert row["n_unique_dst_ip"] == 2 and row["n_unique_dst_port"] == 2


def test_unknown_sources_are_flagged_only_when_an_allow_list_is_given(h):
    events = [h.request(h.T0, "10.60.10.21"), h.request(h.T0, "10.60.30.99")]
    frame = events_to_frame(events)
    without = window_features(frame)
    assert (without["n_new_source"] == 0).all()
    with_list = window_features(frame, known_ips={"10.60.10.21", h.VICTIM})
    flags = dict(zip(with_list["src_ip"], with_list["n_new_source"], strict=True))
    assert flags == {"10.60.10.21": 0, "10.60.30.99": 1}


def test_empty_input_gives_an_empty_frame_with_the_feature_columns():
    windows = window_features(events_to_frame([]))
    assert windows.empty
    assert list(windows.columns) == ["window_start", "src_ip", *FEATURES]
