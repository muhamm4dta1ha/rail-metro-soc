# Module 4 - ML Threat Detection

**Owner: Anum** (ML Lead) - **Reviewer: Furqan** (reviews every PR that touches this folder) - **Rubric:** extension that feeds criterion 3 (SIEM detection)
**Plan:** [plan/PLAN.md section 12](../../plan/PLAN.md) - tasks `M4-01` ... `M4-13`

This module detects threats and attacks with machine learning **and works with all three other modules** (HC-12): it learns from what **Talha's** simulation produces, is trained and scored against **Furqan's** ground truth, and its alerts are shown in **Roshni's** SIEM dashboard. This folder is **starter code** that **Anum** extends on `feature/ml/<TASK-ID>-<slug>` branches; **Furqan** reviews each PR.

## What is here

| Path | What | Anum extends it in |
|---|---|---|
| `railsoc_ml/features.py` | Events -> per-source time-window features (failures, distinct ports/hosts, 4xx/5xx, Modbus writes, MQTT publishes, new sources) | M4-05 |
| `railsoc_ml/dataset.py` | Events + ground truth -> labelled windows; **run-grouped / chronological** split (no leakage) | M4-04 |
| `railsoc_ml/models.py` | `ThresholdBaseline`, `AnomalyDetector` (One-Class SVM by default, Isolation Forest optional; normal-only training), `SupervisedDetector` (random forest) | M4-06 .. M4-08 |
| `railsoc_ml/evaluate.py` | Precision / recall / F1 / FPR / ROC-AUC / PR-AUC, false alarms per hour | M4-09 |
| `railsoc_ml/serve.py` | Scores events and emits `ml.alert` contract events (starter: batch; M4-10: streaming) | M4-10 |
| `railsoc_ml/cli.py`, `configs/default.toml` | `build-dataset`, `train`, `score` commands and defaults | M4-02 |
| `notebooks/`, `reports/`, `models/` | Exploration, feature catalogue / model card / dataset card, model artifacts (not in git) | M4-03, M4-12 |

**Starter finding (re-check on the real campaign data):** on very regular traffic (the starter data has only 3 distinct normal feature vectors) an Isolation Forest cannot extrapolate beyond the training range and scored a 60-failure burst *lower* than normal windows (0.66 vs 0.69); a One-Class SVM on standardised features separated them clearly (1.38 vs 0.0002), so it is the default. Isolation Forest stays available with `--method isolation_forest`.

## Handoffs - who needs what from Anum

| Anum delivers | To | When |
|---|---|---|
| Data needs (volume, benign look-alikes, field requirements) written down early | **Talha** (builds the generator) | Phase 1 |
| Label-validation feedback (mislabels) and requests for more/varied runs | **Furqan** (owns ground truth and campaigns) | Phases 3-4 |
| `ml.alert` event format (already in the schema), model output and metrics for the dashboard ML panel | **Roshni** (ingests alerts, builds the panel) | Phases 4-5 |

## Quick start

```bash
pip install -e ".[dev,ml]"
python -m railsoc_sim.cli generate --hours 4 --seed 1 --out lab/data/raw/normal_s1.jsonl
python -m railsoc_ml.cli build-dataset --events lab/data/raw/normal_s1.jsonl --runs lab/ground_truth/attack_runs.csv --assets src/simulation/config/assets.csv --out lab/data/processed/dataset_v1.csv
python -m railsoc_ml.cli train --dataset lab/data/processed/dataset_v1.csv --out src/ml/models/anomaly.joblib
```

## Rules for this module (hard constraints, see plan/PLAN.md section 2)

- The model must detect the **three required scenarios** and is evaluated on **held-out runs**, never on random rows (HC-12, leakage rule).
- Only fields from the event schema are features; **never** `message` text and **never** labels (HC-19).
- ML alerts are ordinary `ml.alert` events so they land in the same SIEM dashboard as rule alerts; evaluate them with `railsoc_detection.evaluate` so rules and ML are scored the same way (HC-12).
- Synthetic data only; large datasets, models and pcaps stay out of git (HC-03, HC-20).
- New behaviour needs tests in `src/ml/tests/`; CI must be green before merging into `develop` (HC-14).
