# Module 3 - Detection (Wireshark + SIEM)

**Owner: Roshni** (Detection Lead) - **Reviewer: Anum** (reviews every PR that touches this folder) - **Rubric:** criterion 3 (30 marks)
**Plan:** [plan/PLAN.md section 11](../../plan/PLAN.md) - tasks `M3-01` ... `M3-12`

This folder is **starter code**: rule/decoder stubs, an offline linter, an evaluator and documentation skeletons. SIEM = **Wazuh** (HC-05). **Roshni** extends it on `feature/detection/<TASK-ID>-<slug>` branches; **Anum** reviews each PR.

## What is here

| Path | What | Roshni extends it in |
|---|---|---|
| `siem/deploy/README.md` | How to deploy Wazuh single-node (pinned version, WSL2 gotchas) | M3-01 |
| `siem/ossec/` | Agent / manager config snippets (`localfile` entries) | M3-02 |
| `siem/decoders/railsoc_decoders.xml` | Decoders for non-JSON sources (schema events use the JSON decoder) | M3-03 |
| `siem/rules/railsoc_rules.xml` | Starter rules per scenario, reserved id ranges, MITRE mapping | M3-04, M4-11 |
| `siem/queries/queries.md` | Query templates per scenario (validate, add screenshots) | M3-07 |
| `siem/dashboards/` | Final dashboard export (`*.ndjson`) + panel list | M3-08 |
| `wireshark/filters.md`, `wireshark/profile/`, `wireshark/evidence/` | Display filters, importable profile, annotated evidence per scenario | M3-05, M3-06 |
| `railsoc_detection/rule_lint.py` | Offline lint of rules/decoders (runs in CI) | M3-03, M3-04 |
| `railsoc_detection/evaluate.py` | Scores Wazuh alerts **and** ML alerts against the ground truth: detected?, time-to-detect, false alarms | M3-10 |

## Handoffs - who needs what from Roshni

| Roshni delivers | To | When |
|---|---|---|
| Sign-off that every source in the log-source inventory arrives in the SIEM | **Talha** (owns the log sources) | Phase 2 |
| Feedback per scenario: which documented indicators are detectable and which are missing | **Furqan** (owns the scenarios) | Phases 3-4 |
| The SIEM path for `ml.alert` events (rule ids 100400-100499), the dashboard ML panel and Wazuh `alerts.json` exports for evaluation | **Anum** (owns the ML detector) | Phases 4-5 |

## Quick start

```bash
pip install -e ".[dev]"
python -m railsoc_detection.cli lint
python -m railsoc_detection.cli evaluate --wazuh-alerts alerts.json --runs lab/ground_truth/attack_runs.csv --observed-hours 12
```

## Rules for this module (hard constraints, see plan/PLAN.md section 2)

- Detection uses **Wireshark and Wazuh (or Splunk)**: search queries executed, dashboard produced (HC-05).
- Custom Wazuh rule ids stay in `100000-120000`; ranges are reserved per scenario; every rule of level 7 or higher maps to ATT&CK (the lint checks this).
- ML alerts (`ml.alert`) must appear in the same dashboard as rule alerts (HC-12) - agree the format with Anum via `docs/contracts/event_schema.md`.
- Rules must be validated with `wazuh-logtest`; keep the fixtures in `src/detection/tests/fixtures/`.
- Credentials never go into git (`.env` is ignored) (HC-20). New behaviour needs tests; CI must be green before merging into `develop` (HC-14).
