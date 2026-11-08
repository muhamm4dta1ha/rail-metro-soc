"""Validate a session's manifests, hashes, event identities and ground-truth joins."""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from railsoc_common.events import as_utc, read_events
from railsoc_common.groundtruth import label_event, load_runs


def audit(root: Path, ground_truth: Path):
    runs = load_runs(ground_truth)
    ids = [r.run_id for r in runs]
    if len(ids) != len(set(ids)):
        raise ValueError('Duplicate ground-truth run IDs')
    index = {r.run_id: r for r in runs}
    counts = Counter()
    events_total = 0
    identifiers = []
    for path in sorted(root.glob('RUN-*/manifest.json')):
        manifest = json.loads(path.read_text(encoding='utf-8'))
        run = index[manifest['run_id']]
        if manifest['scenario_id'] != run.scenario_id:
            raise ValueError('Manifest and ground truth disagree')
        if as_utc(manifest['start_utc']) != run.start or as_utc(manifest['end_utc']) != run.end:
            raise ValueError('Run window mismatch')
        for filename, expected in manifest['sha256'].items():
            if hashlib.sha256((path.parent/filename).read_bytes()).hexdigest() != expected:
                raise ValueError(f'Hash mismatch: {path.parent/filename}')
        events = list(read_events(path.parent/'events.jsonl', validate=True))
        if len(events) != manifest['event_count']:
            raise ValueError('Event count mismatch')
        for number, event in enumerate(events, start=1):
            if not run.start <= as_utc(event['@timestamp']) <= run.end:
                raise ValueError('Event outside its run window')
            expected = 'benign' if run.scenario_id == 'BASELINE' else 'attack'
            if label_event(event, runs).label != expected:
                raise ValueError('Ground-truth join mismatch')
            # Keep identifiers in an external index; do not change the shared event schema.
            identifiers.append({'file': str(path.parent/'events.jsonl'), 'line': number,
                                'sha256': hashlib.sha256(json.dumps(event, sort_keys=True).encode()).hexdigest()})
        counts[f"{manifest['procedure']}-{'baseline' if run.scenario_id == 'BASELINE' else 'attack'}"] += 1
        events_total += len(events)
    (root/'event_index.jsonl').write_text(''.join(json.dumps(item)+'\n' for item in identifiers), encoding='utf-8')
    summary = {'runs': dict(counts), 'events': events_total, 'unique_file_line_identifiers': len(identifiers),
               'duplicate_run_ids': 0, 'missing_timestamps': 0, 'label_mismatches': 0,
               'event_schema': 'unchanged; external file/line identifiers', 'integrity': 'verified'}
    (root/'audit.json').write_text(json.dumps(summary, indent=2)+'\n', encoding='utf-8')
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('session', type=Path)
    parser.add_argument('--ground-truth', type=Path, default=Path('lab/ground_truth/attack_runs.csv'))
    args = parser.parse_args()
    print(json.dumps(audit(args.session, args.ground_truth), indent=2))


if __name__ == '__main__':
    main()
