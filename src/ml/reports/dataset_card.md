
# Dataset card | dataset_v1

## Inventory at intake

| Input | Files | Records |
|---|---:|---:|
| Existing JSONL logs in the project | 0 | 0 |
| Campaign evidence files or packet captures | 0 | 0 |
| Asset inventory | 1 | 24 |
| Ground-truth CSV | 1 | 0 data rows |

The attack-run CSV contained a header only. Scenarios A, B and C each had zero runs and there were zero explicit baseline runs. There was no timestamp range, label distribution, optional-field coverage or malformed-event count to infer from the empty intake. The campaign has insufficient data for supervised training, held-out attack evaluation or a Wazuh rule comparison.

## Offline normal dataset generated for this delivery

`lab/data/raw/normal_s1.jsonl` contains 66,985 records produced by the repository's normal generator, seed 1, starting at 2026-01-05 00:00 UTC for 12 simulated hours. The first timestamp is `2026-01-05T00:00:00.653Z` and the last is `2026-01-05T11:59:58.607Z`. SHA-256 is `7d7a046511727ebfca80089f2c9999997506fca0ac15abf445541fcd5d511a91`.

| Source dataset | Events |
|---|---:|
| `scada.poll` | 60,000 |
| `pis.app` | 6,966 |
| `auth.ssh` | 12 |
| `scada.command` | 7 |

All 66,985 records passed the shared schema and timestamp checks. There were zero malformed records or missing required fields. All records have source and destination IPv4 addresses and destination ports. HTTP status is present in 6,966 records and latency in 6,924. Modbus function codes occur in 60,007 records and named telemetry values and units in 60,000. MQTT topic, network bytes, network packets and event duration are absent throughout. These are optional fields. The generator includes benign look-alikes such as maintenance writes, occasional failed logins and server errors. It is an offline statistical simulator and these records do not represent captured packets.

## Windows and labels

The generated `lab/data/processed/dataset_v1.csv` is paired with `dataset_v1.meta.json`. Each row is a non-overlapping 10-second UTC bin for one source, with a shared missing-source group where applicable. The row carries the strongest event label in order `attack`, `attack_impact`, `benign`. Ties prefer a recorded run, then the earliest event and run ID. Explicit `BASELINE` labels stay benign. Ground-truth windows that share time are grouped across all sources even when one event could receive several labels. The sidecar preserves the original run intervals for partitioning and evaluation. The campaign-overlap flag excludes all active attack bins from anomaly fit and calibration.

The offline dry run has 8,884 source windows, all labeled `benign`. The chronological split yielded 2,788 training windows, 2,771 validation windows and 3,325 held-out test windows. Tests construct artificial direct, impact and baseline examples, including representative A/B/C event shapes. They are separate from the measured dataset and are used to check code behavior. The [results](results.md) list the measured split sizes and available metrics.
