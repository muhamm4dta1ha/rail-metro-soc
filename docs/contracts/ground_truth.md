# Ground truth (contract v0.1)

**Owner: Furqan** - **Consumers: Roshni** (detection evaluation), **Anum** (ML dataset and labels) - code: `src/common/railsoc_common/groundtruth.py`, file: `lab/ground_truth/attack_runs.csv`

The ground truth says **when** an attack (or a normal BASELINE window) ran, **who** attacked **whom**, and **where the evidence is**. It is the *only* place labels live (HC-19).

## `attack_runs.csv` columns

| Column | Meaning |
|---|---|
| `run_id` | `RUN-<A\|B\|C\|BASELINE>-<UTC yyyymmddThhmmssZ>-<nn>` |
| `scenario_id` | `A` admin access, `B` rogue device, `C` service disruption, `BASELINE` normal comparison window |
| `variant` | free text for parameter variants |
| `start_utc`, `end_utc` | run window, UTC (`end` after `start`) |
| `attacker_ips`, `victim_ips`, `victim_assets` | `;`-separated; **all IPs must be inside the lab** `10.60.0.0/16` (HC-18); BASELINE rows have no attacker |
| `techniques` | ATT&CK ids, `;`-separated |
| `params_json` | scenario parameters (rate, duration, ...) |
| `evidence_dir` | `lab/evidence/runs/<run_id>` |
| `notes` | `status=completed` or `status=aborted; error=...` |

## Labelling rule (`label_event`)

| Label | When |
|---|---|
| `attack` | the event is inside a run window and its source or destination IP is an attacker IP |
| `attack_impact` | inside a run window, involves a victim IP or victim asset, but no attacker IP (collateral) |
| `benign` | everything else; BASELINE runs always give `benign` |

Window level (used by Anum's dataset): a (time window, source IP) row takes the strongest label of its events: `attack` > `attack_impact` > `benign`. `is_attack` = 1 only for `attack`.

## Who does what
- **Furqan** writes the runs (the recorder does it automatically for live runs) and keeps the file valid.
- **Anum** spot-checks labels (20 sampled windows) and reports mislabels back to Furqan (task M2-09).
- **Roshni** evaluates alerts against the runs with `railsoc_detection.evaluate` (task M3-10).

## Changing the contract
Same process as the event schema: PR with code + doc + tests, Furqan (owner) and one consumer approve.
