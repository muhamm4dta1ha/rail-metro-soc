
# Module 4 | ML threat detection

**Owner** Anum Ali · **Reviewer** Furqan

Module 4 reads the shared event JSONL and the separate ground-truth CSV, builds per-source UTC windows, trains and evaluates detectors, and writes schema-valid `ml.alert` JSONL. See the [Module 4 report](../../docs/report/ml_module4.md), [design](../../docs/report/ml_design.md), [dataset card](reports/dataset_card.md), [feature catalogue](reports/feature_catalogue.md), [model card](reports/model_card.md) and [results](reports/results.md).

## Windows PowerShell quick start

Run from the repository root. The generator below is the existing **offline synthetic normal** simulator. Use Talha's lab logs for campaign validation.

```powershell
python -m venv .venv
$python = '.\.venv\Scripts\python.exe'
& $python -m pip install -e '.[dev,ml,sim]'
& $python -m railsoc_sim.cli generate --start '2026-01-05T00:00:00Z' --hours 12 --seed 1 --out lab/data/raw/normal_s1.jsonl
& $python -m railsoc_ml.cli build-dataset --events lab/data/raw/normal_s1.jsonl --assets src/simulation/config/assets.csv
& $python -m railsoc_ml.cli train
& $python -m railsoc_ml.cli compare
& $python -m railsoc_ml.cli score --events lab/data/raw/normal_s1.jsonl --stream
& $python -m pytest src/ml/tests -q
& $python scripts/check_all.py
```

The default inputs, outputs, seeds, window length and thresholds live in [default.toml](configs/default.toml). Pass `--config <file>` before the subcommand to override TOML settings. Per-command flags take precedence. The dataset CSV and matching `.meta.json` stay together. The sidecar records run spans, window length and the asset inventory used during preprocessing. Scoring reuses the artifact's settings. Keep joblib artifacts local and load only artifacts you trust.

`score` reads the entire input in batch mode. With `--stream`, pass a nondecreasing event-time file. The scorer buffers one time bin, defaults to a 100,000-event limit per bin and emits a window when a later bin arrives or at EOF. An out-of-order input or exceeded limit fails the command. The file is replaced only after successful scoring, so replaying the command to the same path does not append duplicate alerts. The incremental API consumes an iterator. The CLI consumes finite files and has no persistent checkpoint across separate input files. Keep each complete window in one input when handing off successive files. Both modes skip input `ml.alert` events to avoid scoring their own output.

The generated comparison includes a Markdown table, JSON metrics, plots and per-model holdout alerts under `src/ml/reports/generated/`. Datasets and full-log alerts go under `lab/data/`. Models go under `src/ml/models/`. These generated outputs are ignored by Git.

## When the campaign logs arrive

Collect the matching UTC event files and the completed ground-truth CSV from Furqan, with normal logs from the same collection setup and supporting evidence. Confirm timestamps, asset/endpoint mappings and unique run IDs. Pass each distinct event file once, since duplicate log lines alter event counts. Keep campaign paths separate from the offline dry run.

```powershell
& $python -m railsoc_ml.cli build-dataset --events lab/data/raw/lab_normal.jsonl --events lab/data/raw/campaign.jsonl --runs lab/ground_truth/attack_runs.csv --assets src/simulation/config/assets.csv --out lab/data/processed/campaign_v1.csv
& $python -m railsoc_ml.cli compare --dataset lab/data/processed/campaign_v1.csv --models-dir src/ml/models/campaign --report-dir src/ml/reports/generated/campaign
```

Choose fractions before reviewing test results. The default chronological targets are 50% train, 20% validation and 30% test. Whole run spans and equal timestamps move the cuts as needed. Check the resulting partition metadata and scenario coverage. If training and validation have too little clean normal traffic, or the test period lacks complete A/B/C runs, request campaign coverage in the affected periods. Random Forest is skipped unless the training slice has both classes and at least two positive runs. This minimum enables a smoke comparison. Stable estimates require more diverse runs for each scenario.

For an aligned Wazuh export, add `--wazuh-alerts lab/data/processed/wazuh_alerts.jsonl` to the campaign comparison. This reuses the M3 evaluator for scenario rule IDs 100100–100399, using the same held-out interval and grace period as ML. The M3 run metric matches by time, so overlapping runs or coincident unrelated alerts can inflate run detection. Window-level ML metrics use the shared labels. Run comparisons require live Wazuh alert timestamps from the same UTC capture period. A later replay uses a different Wazuh ingestion time.

## Wazuh handoff for Roshni

1. Use the [example alert in results](reports/results.md) or export one line with `Get-Content lab/data/processed/ml_alerts.jsonl -TotalCount 1`. The offline example is a benign false positive. Use a dedicated lab validation session for it.
2. Load the existing [RailSOC rules](../detection/siem/rules/railsoc_rules.xml) in the lab manager's rules directory. Open **Tools > Ruleset Test** on the manager dashboard and paste the exact JSON line, or copy the line to the lab manager as `/tmp/ml_alert_sample.jsonl` and run:

   ```sh
   sudo /var/ossec/bin/wazuh-logtest -U 100400:6:json < /tmp/ml_alert_sample.jsonl
   ```

   Confirm decoder `json` and rule `100400`. [Wazuh ruleset testing](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html)
3. To test collection, create an empty `/var/log/railsoc/ml_alerts.jsonl` readable by the lab manager. Add this block inside its `<ossec_config>` and apply the configuration using the team's manager deployment. Append the sample once after the collector starts. For future runs, hand off new lines once to this append-only collector file.

   ```xml
   <localfile>
     <location>/var/log/railsoc/ml_alerts.jsonl</location>
     <log_format>json</log_format>
   </localfile>
   ```

   [Wazuh localfile configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html)
4. In the lab dashboard, search the ingestion time range with `rule.id:100400 AND data.event.dataset:"ml.alert"`. Add `data.ml.model`, `data.ml.score`, `data.ml.threshold` and `data.source.ip` to the ML panel. Expand a row to inspect the original window bounds and top features. Capture the query and expanded row together, and capture the matched decoder and rule in the Ruleset Test screen.

For the local report, open `src/ml/reports/generated/false_positives.png` and `confusion_matrices.png`. Capture either chart together with the report title and the held-out period in `comparison.md` if a screenshot is required. These charts use offline normal data. The Wazuh screenshots require a running lab manager.
