# SIEM queries (task M3-07)

Validated against the real indexed alert data generated for this submission (Wazuh Dashboard,
index `wazuh-alerts-4.x-*`, Discover / DQL or the `_search` API). JSON-decoded schema fields live
under `data.*`; Wazuh's own fields are `rule.id`, `rule.level`, `rule.mitre.id`, `timestamp`.

Dataset this was validated against: 11 live runs each of scenarios A/B/C plus baseline windows,
run through the real simulation lab (`src/simulation/`) and the real attack scenarios
(`src/attacks/`) - see `lab/ground_truth/attack_runs.csv` and `lab/evidence/runs/`. Counts below
are real result counts from that run, not placeholders - re-running the lab will produce
different (but similarly-shaped) numbers.

## Scenario A - unauthorized administrative access

| Question | Query (DQL) | Result (this run) |
|---|---|---|
| Which sources fail to log in to the PIS? | `data.event.dataset:"pis.app" and data.event.action:"login" and data.event.outcome:"failure"` | 164 failures total; `data.source.ip` terms aggregation splits it **10.60.20.99 (attacker): 80** vs **10.60.20.20 (OCC's own benign typo-logins, http_driver.py typo_rate=0.1): 84** - the raw failure count alone does not separate attacker from benign; rule 100101's same-source frequency does. |
| Did a failure burst end in a success, same source? | Two-step (see note): `rule.id:100101 and data.source.ip:"10.60.20.99"` (36 hits, the burst alert) then `data.event.dataset:"pis.app" and data.event.action:"login" and data.event.outcome:"success" and data.source.ip:"10.60.20.99"` within the following ~15 s | Confirms a success shortly after every burst for `10.60.20.99`; **zero** such successes for any other source in this dataset. |
| Which rules fired for scenario A? | `rule.id:(100100 or 100101 or 100103)` | 100100 (failure, level 3): 138 - 100101 (burst, level 10): 37 - 100103 (success, audit, level 3): 24 |

**Note on the two-step query:** a single Wazuh *rule* cannot express "A, then a differently-shaped
B, from the same source" - `if_matched_sid` only re-evaluates the dependent rule on the same event
that also satisfies the target rule's own field conditions, which is structurally impossible when
the two events have mutually exclusive `event.outcome` values (verified with `wazuh-logtest`; see
`docs/report/evaluation.md`). The correlation is done as this two-step SIEM query instead, and
rule 100103 exists *only* so the success event is indexed at all - with `log_alert_level=3`, a
success fired no rule (level 0) and was invisible to every query above.

## Scenario B - unauthorized Modbus reads

| Question | Query (DQL) | Result (this run) |
|---|---|---|
| Who reads PLC-01's registers? | `data.event.dataset:"scada.poll" and data.modbus.function_code:3` | 24 unauthorized reads, **all** from `10.60.20.99`; 0 from any other source in the indexed alert set (approved OCC reads are level 0 / not alerted - see `scada.poll` volume note below). |
| Any source outside the asset inventory doing writes? | `data.event.dataset:"scada.command" and not data.source.ip:("10.60.10.23" or "10.60.20.20")` | 0 in this run (no write-based attack traffic was generated; rule 100200 only fired on OCC's own legitimate maintenance writes before the allow-list fix - see evaluation.md "log-source onboarding findings"). |
| Which rules fired for scenario B? | `rule.id:(100200 or 100201 or 100202)` | 100200 (write, now correctly 0 false positives): 7 (all pre-fix, kept as evidence of the bug) - 100201 (unauthorized read): 3 - 100202 (repeated unauthorized read): 21 |

Approved OCC reads are **not** separately queryable from the alerts index: rule 100201 is a
negative-match rule (fires on everything *except* the approved source), so an approved read never
fires any rule and is never alerted/indexed - consistent with how Wazuh is configured here
(`log_alert_level=3`). To see approved traffic directly, query the raw JSONL evidence
(`lab/data/raw/modbus_live.jsonl`) rather than the SIEM.

## Scenario C - abnormal PIS request rate

| Question | Query (DQL) | Result (this run) |
|---|---|---|
| Are requests rising for one source? | `rule.id:100302` (base rate-tracking rule) then visualise count by `data.source.ip` over a 1 s date histogram | 2651 total; split by source: `10.60.20.99` (attacker, test-phase bursts) vs `10.60.20.20` (OCC's real baseline/background GET /api/arrivals traffic). |
| Which source actually crossed the rate threshold? | `rule.id:100303` | 168 total: **94 from the real attacker** (`10.60.20.99`), **66 attributed to `10.60.20.20`** - all 66 are from early testing where this file was replayed as one static batch instead of tailed live, which compresses real 1 req/s traffic into a sub-second burst and crosses any frequency threshold; confirmed **not** reproducible under real-time tailing (see evaluation.md). Kept in the dataset as honest evidence of the finding, not hidden. |
| Are errors rising (defense-in-depth, original starter check)? | `data.event.dataset:"pis.app" and data.http.response.status_code >= 500` | 0 - the PIS stub (`ThreadingHTTPServer`) never actually returns 5xx under this load; confirms the starter's 5xx-only rule (100300/100301) would never have fired on a real run of this scenario, which is exactly why 100302/100303 were added. |

## ML alerts

| Question | Query (DQL) | Result |
|---|---|---|
| What did the model flag? | `data.event.dataset:"ml.alert"` | See `docs/report/evaluation.md` "ML integration" - status as of this submission. |
| Which rules fired overall? | `rule.id >= 100000 and rule.id < 100500` | Aggregate by `rule.id` and `rule.mitre.id` - full breakdown in `docs/report/evaluation.md`. |

## Reproducing these counts

```bash
# with the lab and Wazuh up (see siem/deploy/README.md)
curl -sk -u admin:<indexer password> \
  "https://localhost:9200/wazuh-alerts-4.x-*/_search?size=0" \
  -H 'Content-Type: application/json' \
  -d '{"aggs":{"by_rule":{"terms":{"field":"rule.id","size":30}}}}'
```
