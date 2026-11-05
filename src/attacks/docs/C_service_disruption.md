# Scenario C - Service disruption (availability)

Status: **starter** (objective + expected indicators). Procedure and runner: task M2-06 - Owner: Furqan - Reviewer: Talha (Roshni checks the indicators)

## Objective
Show how a degradation of the simulated passenger-information service looks to a SOC: traffic far above baseline, rising errors and latency, stale station displays. Brief category: *service disruptions*.

## Scope & safety (stricter than the other scenarios)
- Target: the **simulated** PIS / MQTT broker containers in the isolated lab - nothing else. Attacker: `ATK-01` (10.60.66.10).
- **Time-boxed and rate-capped** by `config/lab_scope.toml` (clamped in code), a kill switch that is tested first, and a watchdog that restores the service afterwards. Never run unattended the first time.
- Must comply with [RULES_OF_ENGAGEMENT.md](../RULES_OF_ENGAGEMENT.md) rule 8.

## ATT&CK mapping (verify ids on attack.mitre.org)
T1499 Endpoint Denial of Service; ICS: T0814 Denial of Service.

## Preconditions
Lab up with normal PIS traffic (M1-04/08), health/latency metrics emitted by the PIS (`svc.health` or `http.response.latency_ms`), SIEM dashboard with a service-health panel (M3-08).

## Procedure (reproducible)
TO WRITE (M2-06): mechanism, pinned tools, parameters (rate, duration), kill-switch test, watchdog/restore, clean-up.

## Expected indicators (by layer)
| Layer | What should be visible |
|---|---|
| Network (Wireshark) | Request/connection rate from the attacker far above the baseline I/O graph; retransmissions, zero-window or reset patterns; MQTT connect/disconnect churn |
| Host / app logs | HTTP 5xx and timeouts, rising `latency_ms`, failed health checks, watchdog/restart events |
| SIEM | Rate-spike rule against the baseline for the time of day, service-down/health-check rule, availability panel turning red |
| ML features | `n_events` per window, `n_http_5xx`, latency statistics, events/second for the attacker's source |

## Expected events (contract datasets)
`pis.app` (web/request with 5xx), `svc.health` (availability), `mqtt.broker`, `gw.firewall`, `net.flow`.

## Evidence collected (per run - automated by the recorder)
`manifest.json`, pcap slice, application and health logs, SIEM alert export, screenshots of the dashboard during and after the run.

## Baseline for comparison (M2-07)
Same time-of-day profile without the attack (including the rush-hour burst, a benign look-alike for "high request rate").

## Mitigation recommendations (input to M2-12 and the report)
- Prevent: rate limiting / connection limits at the gateway, caching of the arrivals feed, resource quotas, redundant broker.
- Detect: baseline-relative rate rule, health-check monitoring, latency SLO alerts.
- Respond: throttle or block the source, fail over to a standby, restore from the watchdog, post-incident review.

## Status checklist
- [ ] procedure written
- [ ] runner implemented (guarded by `ctx.guard`, kill switch tested)
- [ ] indicators confirmed in pcap and logs
- [ ] baseline captured
- [ ] Module 3 detects it
- [ ] Module 4 features cover it
- [ ] reviewed by the ring reviewer
