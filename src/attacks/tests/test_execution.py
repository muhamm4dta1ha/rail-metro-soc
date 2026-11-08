"""Offline transport tests: all sockets are replaced with mocks."""
import json
from unittest.mock import MagicMock

import pytest

from railsoc_attacks import traffic
from railsoc_attacks.recorder import run_scenario
from railsoc_attacks.safety import KillSwitchEngaged, LabScope
from railsoc_attacks.scenario import RunContext
from railsoc_attacks.scenarios import get_scenario
from railsoc_common.events import validate_event
from railsoc_common.groundtruth import load_runs


@pytest.fixture()
def timer(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(traffic.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(traffic.time, 'sleep', lambda delay: clock.__setitem__(0, clock[0] + delay))
    return clock


@pytest.fixture()
def http(monkeypatch):
    factory = MagicMock()
    factory.return_value.getresponse.return_value.status = 200
    monkeypatch.setattr(traffic.http.client, 'HTTPConnection', factory)
    monkeypatch.setenv('M2_PIS_USER', 'test_user')
    monkeypatch.setenv('M2_PIS_PASSWORD', 'test_only_secret')
    return factory


def context(scenario, scope, **params):
    return RunContext('test', scope, {**scenario.default_params, **params}, False)


def test_a_failures_then_success_and_secrets_absent(scope, timer, http):
    scenario = get_scenario('A')
    http.return_value.getresponse.side_effect = [MagicMock(status=401)] * 5 + [MagicMock(status=200)]
    ctx = context(scenario, scope)
    scenario.execute(ctx)
    assert [e['http']['response']['status_code'] for e in ctx.events] == [401] * 5 + [200]
    assert timer[0] == 15
    assert 'test_only_secret' not in json.dumps(ctx.events + ctx.measurements)
    for event in ctx.events:
        validate_event(event)
    assert http.call_args.kwargs['source_address'] == ('10.60.66.10', 0)


def test_a_normal_baseline_one_success(scope, timer, http):
    scenario = get_scenario('A')
    ctx = context(scenario, scope, baseline=True, attacker_ip='10.60.20.20')
    scenario.execute(ctx)
    assert len(ctx.events) == 1
    assert ctx.events[0]['event']['outcome'] == 'success'


def test_missing_account_fails_without_network(scope, timer, http, monkeypatch):
    monkeypatch.delenv('M2_PIS_PASSWORD')
    scenario = get_scenario('A')
    with pytest.raises(ValueError, match='M2_PIS'):
        scenario.execute(context(scenario, scope))
    http.assert_not_called()


@pytest.mark.parametrize('failure', [ConnectionRefusedError, TimeoutError])
def test_unreachable_http_is_observed_not_reported_success(scope, timer, http, failure):
    http.return_value.connect.side_effect = failure()
    scenario = get_scenario('A')
    ctx = context(scenario, scope)
    scenario.execute(ctx)
    assert all(e['event']['outcome'] == 'failure' for e in ctx.events)
    assert all('status_code' not in e['http']['response'] for e in ctx.events)


def test_b_read_only_monitoring_and_bound_source(scope, timer, monkeypatch):
    import pymodbus.client
    factory = MagicMock()
    factory.return_value.read_holding_registers.return_value.isError.return_value = False
    monkeypatch.setattr(pymodbus.client, 'ModbusTcpClient', factory)
    scenario = get_scenario('B')
    ctx = context(scenario, scope)
    scenario.execute(ctx)
    assert len(ctx.events) == 8
    assert [call.args[0] for call in factory.return_value.read_holding_registers.call_args_list] == [0,1,2,3]*2
    factory.return_value.write_register.assert_not_called()
    assert factory.call_args.kwargs['retries'] == 0
    assert factory.call_args.kwargs['source_address'] == ('10.60.30.99', 0)
    assert all(e['modbus']['function_code'] == 3 for e in ctx.events)


def test_b_unreachable(scope, timer, monkeypatch):
    import pymodbus.client
    factory = MagicMock()
    factory.return_value.connect.return_value = False
    monkeypatch.setattr(pymodbus.client, 'ModbusTcpClient', factory)
    scenario = get_scenario('B')
    ctx = context(scenario, scope)
    scenario.execute(ctx)
    factory.return_value.read_holding_registers.assert_not_called()
    assert all(e['event']['outcome'] == 'failure' for e in ctx.events)


def test_c_baseline_spike_recovery_and_duration(scope, timer, http):
    scenario = get_scenario('C')
    ctx = context(scenario, scope)
    scenario.execute(ctx)
    baseline, test, recovery = ctx.measurements
    assert [m['phase'] for m in ctx.measurements] == ['baseline', 'test', 'recovery']
    assert test['rate_per_s'] > baseline['rate_per_s']
    assert recovery['successes'] > 0
    assert all(m['failures'] == 0 for m in ctx.measurements)
    assert timer[0] <= 12.00001


@pytest.mark.parametrize('duration', [4, 5, 6])
@pytest.mark.parametrize('baseline', [True, False])
def test_short_c_phases_keep_recovery_probe(scope, timer, http, duration, baseline):
    scenario = get_scenario('C')
    ctx = context(scenario, scope, duration_s=duration, baseline=baseline,
                  attacker_ip='10.60.20.20' if baseline else '10.60.20.99')
    scenario.execute(ctx)
    assert all(m['successes'] > 0 for m in ctx.measurements)
    assert timer[0] <= duration + 0.00001


def test_budget_clock_advances_between_reads(scope, monkeypatch):
    now = [0.0]
    def advancing_clock():
        now[0] += 0.007
        return now[0]
    def sleep(delay):
        assert delay >= 0
        now[0] += delay
    monkeypatch.setattr(traffic.time, 'monotonic', advancing_clock)
    monkeypatch.setattr(traffic.time, 'sleep', sleep)
    scenario = get_scenario('C')
    budget = traffic.Budget(context(scenario, scope, duration_s=1, rate_per_s=50))
    while budget.slot('10.60.20.10'):
        pass


@pytest.mark.parametrize('sid', ['A', 'B', 'C'])
def test_direct_dry_run_does_not_open_sockets(sid, scope, http, monkeypatch):
    import pymodbus.client
    modbus = MagicMock()
    monkeypatch.setattr(pymodbus.client, 'ModbusTcpClient', modbus)
    scenario = get_scenario(sid)
    ctx = context(scenario, scope)
    ctx.dry_run = True
    scenario.execute(ctx)
    http.assert_not_called()
    modbus.assert_not_called()


def test_rate_and_duration_enforced_during_execute(tmp_path, timer, http):
    scope = LabScope(max_rate_per_s=2, max_duration_s=2, kill_switch_file=tmp_path/'kill')
    scenario = get_scenario('A')
    ctx = context(scenario, scope, rate_per_s=999, duration_s=999)
    starts = []
    http.return_value.connect.side_effect = lambda: starts.append(timer[0])
    scenario.execute(ctx)
    assert starts == [0, .5, 1, 1.5]
    assert timer[0] == 2


def test_kill_during_wait_stops_next_request(scope, timer, http):
    scenario = get_scenario('A')
    http.return_value.getresponse.side_effect = lambda: (scope.kill_switch_file.touch() or MagicMock(status=401))
    with pytest.raises(KillSwitchEngaged):
        scenario.execute(context(scenario, scope))
    assert http.return_value.request.call_count == 1


@pytest.mark.parametrize('sid', ['A', 'B', 'C'])
@pytest.mark.parametrize('value', [0, -1, float('nan'), float('inf')])
def test_invalid_rate_rejected(sid, value, tmp_path):
    with pytest.raises(ValueError):
        run_scenario(get_scenario(sid), {'rate_per_s': value}, evidence_dir=tmp_path)


def test_wrong_lab_asset_rejected(tmp_path):
    with pytest.raises(ValueError, match='only supports'):
        run_scenario(get_scenario('A'), {'target_ip': '10.60.20.30'}, evidence_dir=tmp_path)


def test_secret_parameter_rejected_before_manifest(tmp_path):
    with pytest.raises(ValueError, match='Secrets'):
        run_scenario(get_scenario('A'), {'password': 'private'}, evidence_dir=tmp_path)
    assert not list(tmp_path.iterdir())


def test_baseline_recorder_and_integrity(tmp_path, scope, timer, http):
    result = run_scenario(get_scenario('A'), {'baseline': True, 'attacker_ip':'10.60.20.20'},
                          scope=scope, dry_run=False, evidence_dir=tmp_path/'ev',
                          ground_truth_csv=tmp_path/'gt.csv')
    run, = load_runs(tmp_path/'gt.csv')
    assert run.scenario_id == 'BASELINE' and not run.attacker_ips
    manifest = json.loads(result.manifest_path.read_text())
    assert manifest['event_count'] == 1
    assert 'events.jsonl' in manifest['sha256']
    assert (result.manifest_path.parent/'SHA256SUMS').exists()


def test_same_second_run_ids_do_not_overwrite(tmp_path, noop_cls, scope, t0):
    kwargs = dict(evidence_dir=tmp_path, clock=lambda:t0, scope=scope)
    first = run_scenario(noop_cls(), **kwargs)
    second = run_scenario(noop_cls(), **kwargs)
    assert first.run.run_id != second.run.run_id


def test_missing_target_configuration(scope):
    scenario = get_scenario('B')
    with pytest.raises(KeyError):
        scenario.plan({'attacker_ip': '10.60.30.99'})


def test_audit_rejects_changed_events(tmp_path, scope, timer, http):
    from railsoc_attacks.audit_evidence import audit
    root = tmp_path/'session'
    gt = tmp_path/'gt.csv'
    result = run_scenario(get_scenario('A'), {'baseline': True, 'attacker_ip':'10.60.20.20'},
                          scope=scope, dry_run=False, evidence_dir=root, ground_truth_csv=gt)
    assert audit(root, gt)['label_mismatches'] == 0
    events = result.manifest_path.parent/'events.jsonl'
    events.write_text(events.read_text() + '\n')
    with pytest.raises(ValueError, match='Hash mismatch'):
        audit(root, gt)


def test_cli_live_requires_explicit_preflight_flags(tmp_path):
    from railsoc_attacks.cli import main
    with pytest.raises(SystemExit):
        main(['run', 'C', '--live', '--evidence-dir', str(tmp_path)])
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize('value', [0, -1, float('nan'), float('inf')])
def test_invalid_duration_rejected_before_recording(tmp_path, value):
    with pytest.raises(ValueError):
        run_scenario(get_scenario('C'), {'duration_s': value}, evidence_dir=tmp_path)
    assert not list(tmp_path.iterdir())
