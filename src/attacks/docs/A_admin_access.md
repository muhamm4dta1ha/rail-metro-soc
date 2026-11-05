# Scenario A - Unauthorized administrative access

Status: **starter** (objective + expected indicators). Procedure and runner: task M2-04 - Owner: Furqan - Reviewer: Talha (Roshni checks the indicators)

## Objective
Show how unauthorized administrative access to the simulated passenger-information admin portal / maintenance jump host looks to a SOC: from repeated failed logins to a successful login and an out-of-policy administrative action. Brief category: *unauthorized administrative access*.

## Scope & safety
- Target: simulated PIS (`PIS-01`, 10.60.20.10) and jump host (`JH-01`) only. Attacker: `ATK-01` (10.60.66.10) inside the isolated lab.
- Synthetic accounts only (from `src/simulation/.env`). Caps from `config/lab_scope.toml`; kill switch tested before the first live run.
- Must comply with [RULES_OF_ENGAGEMENT.md](../RULES_OF_ENGAGEMENT.md).

## ATT&CK mapping (verify ids on attack.mitre.org)
T1110 Brute Force; T1078 Valid Accounts (the attacker ends up with a valid lab account).

## Preconditions
Lab up with the normal traffic profile (M1-03/04/06), SIEM ingesting the PIS and jump-host logs (M3-02), baseline window recorded (M2-07).

## Procedure (reproducible)
TO WRITE (M2-04): steps, tools + pinned versions, parameters (rate, duration, source, start offset), start/stop commands, clean-up.

## Expected indicators (by layer)
| Layer | What should be visible |
|---|---|
| Network (Wireshark) | Many short HTTP/SSH sessions from `ATK-01` to `PIS-01` / `JH-01`; a burst of `http.response.code == 401`; then one success followed by administrative requests |
| Host / app logs | `pis.app` login failures sharing one `source.ip`; a later login success; an admin/config action by that session; `auth.ssh` failures on the jump host |
| SIEM | Failure-burst rule (frequency over a short timeframe), success-after-failures correlation, admin action outside the maintenance window |
| ML features | `n_failures`, `failure_ratio`, `n_new_source`, `n_events` for the attacker's source in each window |

## Expected events (contract datasets)
`pis.app` (authentication/login failures then success, configuration events), `auth.ssh`, `gw.firewall` allow/deny entries.

## Evidence collected (per run - automated by the recorder)
`manifest.json`, pcap slice from the gateway, `pis.app` / `auth.ssh` log slices, Wazuh alert export, Wireshark and dashboard screenshots under `lab/evidence/runs/<run_id>/`.

## Baseline for comparison (M2-07)
Same duration and traffic profile without the attack. It contains benign look-alikes: occasional typo failures by normal staff and night-window maintenance logins.

## Mitigation recommendations (input to M2-12 and the report)
- Prevent: MFA for administrators, account lockout / rate limiting, source allow-listing for admin interfaces, separate admin plane.
- Detect: failure-burst rule, success-after-failure correlation, new-source alert.
- Respond: block the source, force credential reset, review configuration changes made by the session.

## Status checklist
- [ ] procedure written
- [ ] runner implemented (guarded by `ctx.guard`)
- [ ] indicators confirmed in pcap and logs
- [ ] baseline captured
- [ ] Module 3 detects it
- [ ] Module 4 features cover it
- [ ] reviewed by the ring reviewer
