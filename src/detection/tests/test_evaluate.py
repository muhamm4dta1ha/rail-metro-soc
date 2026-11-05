import json
from datetime import UTC, datetime, timedelta

from railsoc_common.events import make_event, write_events
from railsoc_common.groundtruth import AttackRun
from railsoc_common.ids import new_run_id
from railsoc_detection.cli import main
from railsoc_detection.evaluate import (
    Alert,
    alerts_from_events,
    alerts_from_wazuh,
    evaluate,
    format_markdown,
)

T0 = datetime(2026, 1, 5, 9, 0, tzinfo=UTC)


def run(scenario, offset_min, seq=1):
    start = T0 + timedelta(minutes=offset_min)
    return AttackRun(
        run_id=new_run_id(scenario, start, seq),
        scenario_id=scenario,
        start=start,
        end=start + timedelta(minutes=2),
        attacker_ips=() if scenario == "BASELINE" else ("10.60.66.10",),
        victim_ips=("10.60.20.10",),
    )


def alert(offset_s, source="wazuh:100101"):
    return Alert(ts=T0 + timedelta(seconds=offset_s), source=source)


def test_detection_time_to_detect_and_false_alarms():
    run_a = run("A", 0)  # window 09:00:00 - 09:02:00
    run_c = run("C", 10)  # window 09:10:00 - 09:12:00 - never alerted
    alerts = [alert(45), alert(60), alert(135), alert(3000)]  # +135 s is inside the 30 s grace
    result = evaluate(alerts, [run_a, run_c, run("BASELINE", 30)], observed_hours=2)

    by_id = {r.run_id: r for r in result.runs}
    assert by_id[run_a.run_id].detected and by_id[run_a.run_id].time_to_detect_s == 45
    assert by_id[run_a.run_id].n_alerts == 3
    assert not by_id[run_c.run_id].detected and by_id[run_c.run_id].time_to_detect_s is None
    assert result.detection_rate == 0.5
    assert result.false_alarms == 1  # the alert at +3000 s
    assert result.false_alarms_per_hour == 0.5
    assert len(result.runs) == 2  # BASELINE is not an attack run


def test_min_level_filters_weak_alerts():
    weak = Alert(ts=T0 + timedelta(seconds=10), source="wazuh:100100", level=3)
    strong = Alert(ts=T0 + timedelta(seconds=20), source="wazuh:100101", level=10)
    result = evaluate([weak, strong], [run("A", 0)], min_level=7)
    assert result.runs[0].time_to_detect_s == 20


def test_wazuh_export_with_offset_without_colon_is_parsed(tmp_path):
    lines = [
        {
            "timestamp": "2026-01-05T09:00:45.120+0000",
            "rule": {"id": "100101", "level": 10},
            "data": {"source": {"ip": "10.60.66.10"}},
        },
        {"timestamp": "2026-01-05T09:01:00.000+0000", "rule": {"id": "100100", "level": 3}},
    ]
    path = tmp_path / "alerts.json"
    path.write_text("\n".join(json.dumps(line) for line in lines) + "\n", encoding="utf-8")
    alerts = alerts_from_wazuh(path)
    assert alerts[0].ts == T0 + timedelta(seconds=45, milliseconds=120)
    assert alerts[0].source == "wazuh:100101" and alerts[0].src_ip == "10.60.66.10"
    assert alerts[1].level == 3 and alerts[1].src_ip is None


def test_ml_alert_events_are_parsed_and_other_events_ignored(tmp_path):
    ml = make_event(
        "ml.alert",
        "intrusion_detection",
        "anomaly_detected",
        ts=T0 + timedelta(seconds=50),
        host={"name": "ml-detector"},
        source={"ip": "10.60.66.10"},
        ml={"model": "isolation_forest", "score": 0.9, "threshold": 0.6},
    )
    other = make_event("pis.app", "web", "request", ts=T0, host={"name": "pis-01"})
    path = tmp_path / "events.jsonl"
    write_events(path, [other, ml])
    (parsed,) = alerts_from_events(path)
    assert parsed.source == "ml:isolation_forest" and parsed.src_ip == "10.60.66.10"


def test_markdown_report_and_cli(tmp_path, capsys):
    from railsoc_common.groundtruth import write_runs

    runs_csv = tmp_path / "runs.csv"
    write_runs(runs_csv, [run("A", 0)])
    alerts = tmp_path / "alerts.json"
    alerts.write_text(
        json.dumps({"timestamp": "2026-01-05T09:00:10.000+0000", "rule": {"id": "1", "level": 5}})
        + "\n",
        encoding="utf-8",
    )
    rc = main(["evaluate", "--wazuh-alerts", str(alerts), "--runs", str(runs_csv), "--observed-hours", "1"])
    out = capsys.readouterr().out
    assert rc == 0 and "| RUN-A-20260105T090000Z-01 | A | yes | 10.0 | 1 |" in out
    assert "Detection rate: 100%" in out and "False alarms per hour: 0.00" in out
    assert format_markdown(evaluate([], [])).startswith("| run |")


def test_lint_command_passes_on_the_shipped_siem_folder(capsys):
    siem = __import__("pathlib").Path(__file__).resolve().parents[1] / "siem"
    assert main(["lint", "--siem-dir", str(siem)]) == 0
    assert "0 issue(s)" in capsys.readouterr().out
