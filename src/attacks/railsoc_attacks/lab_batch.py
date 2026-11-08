"""Execute a verified lab batch inside its Docker network namespace."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from railsoc_attacks.campaign import run_campaign
from railsoc_attacks.recorder import run_scenario
from railsoc_attacks.scenarios import get_scenario


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('scenario', choices=['A', 'B', 'C'])
    parser.add_argument('--baseline', action='store_true')
    parser.add_argument('--campaign', action='store_true')
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    out = Path(args.out)
    scenario = get_scenario(args.scenario)
    base = {'attacker_ip': '10.60.20.20' if args.baseline else '10.60.20.99',
            'baseline': args.baseline, 'duration_s': 6, 'rate_per_s': 2, 'request_count': 6}
    if args.scenario == 'C':
        base['rate_per_s'] = 8
    kwargs = {'dry_run': False, 'evidence_dir': out,
              'ground_truth_csv': Path('lab/ground_truth/attack_runs.csv')}
    if args.campaign:
        rates = [4, 6, 8, 10, 12] if args.scenario == 'C' else [2, 3, 4, 5, 6]
        results = run_campaign(scenario, {'rate_per_s': rates, 'duration_s': [4, 5]},
                               base=base, **kwargs)
    else:
        results = [run_scenario(scenario, base, **kwargs)]
    ok = True
    for result in results:
        manifest = json.loads(result.manifest_path.read_text())
        measurements = manifest['measurements']
        if args.scenario == 'A':
            passed = (len(measurements) == (1 if args.baseline else 6)
                      and all(m['status'] == m['expected_status'] for m in measurements))
        elif args.scenario == 'B':
            passed = bool(measurements) and all(m['success'] for m in measurements)
        else:
            passed = (len(measurements) == 3 and all(m['successes'] > 0 for m in measurements))
        ok &= passed
        print(json.dumps({'run_id': result.run.run_id, 'procedure': args.scenario,
                          'baseline': args.baseline, 'observations_match': passed,
                          'events': manifest['event_count'], 'measurements': measurements}), flush=True)
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
