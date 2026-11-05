# Scenario <ID> - <title>

Status: <starter | procedure written | runner implemented | evidence complete | reviewed> - Owner: Furqan - Reviewer: Talha (and Roshni checks the indicators)

## Objective
What should a SOC analyst learn from this scenario? Which brief category does it cover?

## Scope & safety
Targets, attacker host, caps (rate/duration), kill-switch test date. Must comply with [RULES_OF_ENGAGEMENT.md](RULES_OF_ENGAGEMENT.md).

## ATT&CK mapping
Technique ids (verify on attack.mitre.org) and why they apply.

## Preconditions
Lab components that must be up, traffic profile, SIEM ingestion, baseline captured.

## Procedure (reproducible)
Numbered steps, tools + pinned versions, parameters (rate, duration, source, start offset), how to start/stop (`python -m railsoc_attacks.cli run <ID> --live`), clean-up (`reset_lab`).

## Expected indicators (by layer)
| Layer | What should be visible |
|---|---|
| Network (Wireshark) | |
| Host / application logs | |
| SIEM (rules, queries) | |
| ML features | |

## Expected events (contract datasets)
Which `event.dataset` / `event.action` values appear, and in what order.

## Evidence collected (per run)
Manifest, pcap slice, log slices, SIEM alert export, screenshots - paths under `lab/evidence/runs/<run_id>/`.

## Baseline for comparison
The matching normal-activity window (same duration/profile) and the benign look-alikes it contains.

## Mitigation recommendations
Prevent / detect / respond, each tied to an observed indicator.

## Status checklist
- [ ] procedure written
- [ ] runner implemented (guarded by `ctx.guard`)
- [ ] indicators confirmed in pcap and logs
- [ ] baseline captured
- [ ] Module 3 detects it (rules / queries / Wireshark)
- [ ] Module 4 features cover it
- [ ] reviewed by the ring reviewer
