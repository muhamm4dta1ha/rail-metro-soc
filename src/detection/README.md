# Module 3 - Detection (Wireshark + SIEM)

**Owner: Roshni** (Detection Lead) - **Reviewer: Anum** (reviews every PR that touches this folder) - **Rubric:** criterion 3 (30 marks)
**Plan:** [plan/PLAN.md section 11](../../plan/PLAN.md) - tasks `M3-01` ... `M3-12`

**Status: implemented and validated against a real, live lab run** - a real Wazuh 4.9.2
single-node deployment, real traffic from the real simulation lab, real attack runs (M2's
scenarios actually executed, not simulated), real Wireshark packet evidence, real Wazuh alerts,
and a real ML pass over the real data. Full writeup, including two real bugs found and fixed
during log-source onboarding and the exact numbers behind every claim above:
**[docs/report/evaluation.md](../../docs/report/evaluation.md)** - read that first.

SIEM = **Wazuh** (HC-05). **Roshni** extends this on `feature/detection/<TASK-ID>-<slug>`
branches; **Anum** reviews each PR. (This pass was done directly rather than through that PR flow
because, going in, M2's evidence did not exist anywhere yet - see evaluation.md section 0 - so
generating it was a prerequisite for M3 to have anything real to detect. Open the PR from here
through the normal flow for review.)

## What is here

| Path | What | Status |
|---|---|---|
| `siem/deploy/README.md`, `siem/deploy/wazuh-docker/` | Wazuh single-node deployment (pinned 4.9.2), RailSOC overrides (localhost-only ports, `.env` credentials, log mounts, the index-template fix) | **done** (M3-01) |
| `siem/decoders/railsoc_decoders.xml` | Decoders for non-JSON sources (schema events use the JSON decoder) | starter (M3-03, non-JSON sources not yet in scope) |
| `siem/rules/railsoc_rules.xml` | Detection rules per scenario, validated with `wazuh-logtest` and against a live manager | **done** (M3-04) |
| `siem/queries/queries.md` | Real queries with real result counts | **done** (M3-07) |
| `siem/dashboards/railsoc_dashboard.ndjson`, `siem/dashboards/screenshots/` | Real dashboard export (10 panels) + a real browser screenshot of it rendering the real indexed data | **done** (M3-08) |
| `wireshark/filters.md`, `wireshark/evidence/*.pcapng` | Display filters + real merged/de-duplicated pcaps; counts in evaluation.md | **done** (M3-05/M3-06); `wireshark/profile/` (importable colouring profile) still open |
| `railsoc_detection/rule_lint.py` | Offline lint of rules/decoders (runs in CI) | done, 0 issues |
| `railsoc_detection/evaluate.py` | Scores Wazuh alerts **and** ML alerts against the ground truth: detected?, time-to-detect, false alarms | **run against real data** - results in evaluation.md |
| `docs/report/playbooks.md` | Detect/triage/contain/recover per scenario, plus ML alerts | **done** (M3-09) |
| `docs/report/evaluation.md` section 11 | Threshold tuning changelog: every rule change, why, and the evidence for it | **done** (M3-11) |
| `lab/ops/` (repo root) | Additive evidence-generation harness: the attacker container this module needed but didn't exist yet, packet capture at the victims, the dashboard-building script, and a headless-browser screenshot script | new, M3-specific, does not touch M1/M2 |

Still open (see evaluation.md section 12): an importable Wireshark colouring profile
(`wireshark/profile/`) - the filters themselves were all used and validated against real pcaps,
just not packaged as one. No active-response/automatic containment is configured anywhere in this
lab, deliberately (HC-02/HC-18) - every playbook "contain" step is a manual action.

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
