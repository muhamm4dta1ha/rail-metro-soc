# Module 2 - Attack Generation

**Owner: Furqan** (Attack Lead) - **Reviewer: Talha** (reviews every PR that touches this folder) - **Rubric:** criterion 2 (30 marks)
**Plan:** [plan/PLAN.md section 10](../../plan/PLAN.md) - tasks `M2-01` ... `M2-12`

This folder is **starter code**: a safety-first harness plus metadata for the three required scenarios. The scenario runners themselves (`execute()`) are **Furqan's** to implement in tasks M2-04/05/06 - inside the guardrails. **Talha** reviews the PRs; **Roshni** checks that the documented indicators are really detectable.

## What is here

| Path | What |
|---|---|
| `RULES_OF_ENGAGEMENT.md` | Rules every scenario obeys (lab-only, caps, kill switch). All four sign off in task M2-01 |
| `config/lab_scope.toml` | Allowed CIDRs (can only be narrowed), rate/duration caps, kill-switch file |
| `railsoc_attacks/safety.py` | `LabScope`: refuses non-lab targets and hostnames, clamps caps, kill switch |
| `railsoc_attacks/scenario.py` | `ScenarioBase`, `RunContext.guard(ip)` - call it before **any** traffic |
| `railsoc_attacks/recorder.py` | One call = guarded run + `manifest.json` + ground-truth row (dry-run by default) |
| `railsoc_attacks/campaign.py` | Parameter sweeps for many varied runs (Anum needs >= 10 per scenario) |
| `railsoc_attacks/scenarios/` | `a_admin_access.py`, `b_rogue_device.py`, `c_service_disruption.py` (metadata + TODO) |
| `docs/` + `SCENARIO_TEMPLATE.md` | Per-scenario documentation: procedure, indicators, events, evidence, baseline, mitigations |

## Handoffs - who needs what from Furqan

| Furqan delivers | To | When |
|---|---|---|
| Requirements for attacker placement, reset and "hard-negative" look-alike traffic | **Talha** (builds them into the lab) | Phase 1 |
| Documented expected indicators, evidence packs (pcap slices, logs) and matching baseline windows per scenario | **Roshni** (writes rules/queries and the Wireshark evidence) | Phases 2-3 |
| `lab/ground_truth/attack_runs.csv` plus campaign runs (>= 10 varied runs per scenario) | **Anum** (builds `dataset_v1`, validates labels) | Phase 3 |

## Quick start

```bash
pip install -e ".[dev]"
python -m railsoc_attacks.cli list
python -m railsoc_attacks.cli run A      # dry run: writes a manifest, sends NO traffic
```

## Rules for this module (hard constraints, see plan/PLAN.md section 2)

- **Exactly three scenarios** (A admin access, B rogue device, C service disruption). Extra *variants* are fine; extra scenario categories are not (HC-04).
- Lab-only, synthetic-only, never anything operational; safety-related functions are out of scope (HC-02, HC-03, HC-18).
- Every `execute()` calls `ctx.guard(ip)` before sending traffic; no scenario may bypass `railsoc_attacks.safety`.
- Ground-truth labels live only in `lab/ground_truth/attack_runs.csv` - never in event logs (HC-19).
- New behaviour needs tests in `src/attacks/tests/`; CI must be green before merging into `develop` (HC-14). CI never sends live traffic.
