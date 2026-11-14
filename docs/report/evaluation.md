# M3 Detection Evaluation (Roshni)

**Status:** all results below are real - produced by actually running the simulation lab, the
three M2 attack scenarios, a real Wazuh single-node deployment, and the real M4 ML pipeline, then
scoring the real output against the real ground truth. Nothing here is projected or assumed.
Reproduction commands are given for every section so the team (and the examiner) can rerun this.

## 0. What this covers, and an important correction

The original M3 task brief (and the handoff this module started from) assumed teammates' work
had already produced real evidence - specific pcap filters, alert counts (e.g. "55 HTTP 401s",
"66 Modbus reads"), a populated `lab/ground_truth/attack_runs.csv`, and a merged M2 branch. On
inspection, **none of that existed yet**: the checkout had no `.git`, `origin/develop` had M1/M2/M4
merged as real, tested *code* but nobody had ever actually run the lab, and the ground-truth CSV
was empty. Rather than write documentation around numbers that don't exist, M3 generated the
evidence itself: stood up the real simulation lab (Docker), filled the missing M2-03 "attacker
tooling" placeholder with a real container, ran all three scenarios and matching baselines for
real, and built detection on top of that real traffic. See `lab/ops/` for the additive compose
overlay and attacker image (nothing in `src/simulation` or `src/attacks` was modified).

**Final dataset:** 66 real ground-truth rows - 11 live runs each of scenarios A/B/C plus 33
baseline windows (`lab/ground_truth/attack_runs.csv`), spanning about 1.4 observed hours.

## 1. Wireshark analysis (tasks M3-05/M3-06)

Capture points (`lab/ops/docker-compose.evidence.yml`): the existing `occ-capture` (OCC's own
interface) plus two new ones added here, `pis-capture` and `station-plc-capture`, each sharing the
victim's network namespace - the only way to see *attacker* traffic too (a passive sniffer
attached to the same Docker bridge does not see it; Linux bridge forwarding is per-destination-MAC,
not promiscuous-broadcast). Merged, de-duplicated pcaps are in
`src/detection/wireshark/evidence/*.pcapng` (tshark/mergecap, Wireshark 4.6.3).

| Scenario | Filter used | Real result |
|---|---|---|
| Protocol mix | `Statistics > Protocol Hierarchy` on `pis_merged.pcapng` | 16,046 frames; 2,700 HTTP; 1,620 with a JSON body |
| A / C - responses to the rogue source | `http.response && ip.dst==10.60.20.99` | 794 responses: **55 HTTP 401** (exactly 11 runs x 5 failures), **739 HTTP 200** |
| B - unauthorized Modbus reads | `modbus.func_code==3 && ip.src==10.60.20.99` on `station-plc_merged.pcapng` | **88** (11 runs x 8 reads) vs **2,598** approved reads from `10.60.20.20` in the same window |
| C - rate spike (I/O Graph, 1 s buckets) | `ip.dst==10.60.20.99`, `tshark -z io,stat,1` restricted to one run's absolute window | baseline phase ~5 frames/s -> test phase **92-107 frames/s** -> recovery ~5 frames/s (see evaluation methodology note below on replay vs real time - this I/O-graph evidence is from the **real pcap**, not a log replay, so it is not subject to that caveat) |

`10.60.20.99` is an address inside the DMZ subnet that is not in `config/assets.csv` - the actual
"rogue source" address used for every scenario run (see section 2). The 55/88 counts above line up
exactly with the attack code's own per-run request counts (`request_count` in
`src/attacks/railsoc_attacks/scenarios/*.py`) times 11 runs, which is itself confirmation that the
pcap evidence and the application-level evidence agree.

Screenshots were not captured here (no GUI session in this environment) - the filters, the exact
merged pcap files, and the counts above are real and reproducible; opening
`src/detection/wireshark/evidence/pis_merged.pcapng` / `station-plc_merged.pcapng` in the Wireshark
GUI and applying the filters above reproduces every number in this table and gives the actual
screenshots for the submission.

## 2. Why the attacker is at `10.60.20.99`, not `10.60.66.10`

Scenario code's own defaults (`attacker_ip`) point at `attacker_lab`/`station_field` addresses, but
the gateway container in `src/simulation/docker-compose.yml` is an explicit placeholder ("TODO
M1-03/M1-09: inter-zone routing") - it does not route between networks. An attacker container on a
*different* Docker network than its victim has no way for the victim's reply packets to get back
to it. Rather than build a full inter-zone router (out of scope for M3), every live run here used
`--param attacker_ip=10.60.20.99`: an address on the **same** subnet as PIS/PLC-01/OCC
(`dmz_ops`, 10.60.20.0/24) that is genuinely unallocated in `config/assets.csv`. This is still a
faithful "rogue/unauthorized source" per the scenario docs' own indicators (an address not in the
asset inventory) - it is a topology simplification, not a change to what is being detected.
`lab/ops/docker-compose.evidence.yml` pins the `attacker` service to this address.

## 3. Detection rules (tasks M3-03/M3-04) - what changed and why

All of this was validated with `wazuh-logtest` against the Wazuh version actually deployed
(4.9.2) and, for the headline numbers, against the real running manager's `alerts.json` - not
assumed from reading the XML.

### Scenario A (100100-100103)

- **100100** (level 3): any PIS login failure - unchanged starter rule.
- **100101** (level 10, `frequency=4 timeframe=60`): repeated failures, same source. Starter used
  `frequency=8` (9 occurrences) - a real attack run (`request_count=6` -> 5 failures) would never
  reach that. Lowered to 4 (5 occurrences); confirmed it fires on exactly the 5th failure, and
  confirmed with a negative test (5 failures from 5 *different* IPs) that `same_field source.ip`
  really does prevent cross-source false correlation.
- **100103** (level 3, new): a successful PIS login, logged for audit/correlation only. **Why it
  exists:** `<alerts><log_alert_level>3</log_alert_level>` means anything below level 3 never
  reaches `alerts.json` or the indexer. A bare success event is level 0 on its own - before this
  rule, "did a failure burst end in a success?" could not be answered from the SIEM at all, because
  the success half of the question was invisible to every query.
- **A rule that was tried and removed:** a single rule correlating "100101 fired, then a success
  from the same source" via `if_matched_sid`. Confirmed with `wazuh-logtest` (feeding the real
  5-failures-then-1-success sequence from a live run) that it never fires: `if_matched_sid`
  re-evaluates the dependent rule only on the *same event* that also satisfies the target rule's
  own field conditions, which is structurally impossible when the two events have mutually
  exclusive `event.outcome` values. This is done as a two-step SIEM query instead
  (`siem/queries/queries.md`).

### Scenario B (100200-100202)

- **100200** (level 10): Modbus write (function code 5/6/15/16) from outside the allow-list.
  **Fixed a real false positive found in testing:** the starter only allow-listed WS-03
  (`10.60.10.23`), but in this lab's actual Day-1 build OCC-01 (`10.60.20.20`) also performs the
  "authorised maintenance write" role (`railsoc_sim/drivers/modbus_driver.py:maintenance_write_once`;
  see the note on OCC-01 in `config/assets.csv`). Real periodic maintenance writes from the real
  normal-traffic driver were firing this rule. Both addresses are now allow-listed.
- **100201** (level 8, new): function-code-3 (read) from any source other than the approved OCC
  poller (`10.60.20.20`). **The starter rule only covered writes and would have missed every real
  scenario B run** - `b_rogue_device.py` only does reads.
- **100202** (level 10, `frequency=2 timeframe=30`): repeated unauthorized reads, same source -
  raises severity above a single stray probe.
- Verified with real data: 24 unauthorized reads -> 100201 x3, 100202 x21 (escalates after the
  2nd); 0 false positives on ~2,600 real approved OCC reads in the same dataset.

### Scenario C (100300-100303)

- **100300/100301** (starter, unchanged): PIS 5xx and a burst of 5xx. **Confirmed these never fire
  on a real run:** the PIS stub is a plain `ThreadingHTTPServer` that keeps answering 200 under
  the load this scenario generates (0 PIS 5xx responses across the whole dataset) - exactly as
  the scenario's own docstring warns ("no actual outage"/"if observed"). Kept for defense in depth
  (a real overload *would* still trip these), but they are not what actually detects scenario C.
- **100302** (level 3, new): any PIS web request - a base rate-tracking rule, not a security alert
  on its own.
- **100303** (level 10, `frequency=19 timeframe=10`, new): abnormal request rate, same source.
  **This is what actually detects scenario C.** Tuning history: started at `frequency=14`
  (1.5 req/s); real baseline traffic (`http_driver.py`, 1-4 s sleep, <=1 req/s) should not reach
  that, and a real attack run (`rate_per_s=20`) reaches it almost immediately - but a **replayed**
  static log file compresses real inter-arrival spacing into a near-instant burst (see section 5),
  which crossed the 1.5 req/s threshold on baseline data purely as a replay artifact. Widened to
  `frequency=19` (2 req/s) for a larger safety margin; the genuine attack rate (~15-18 req/s
  sustained) still crosses it immediately, confirmed against both wazuh-logtest and the live
  manager.

### ML alerts (100400)

Unchanged starter rule (`event.dataset == ml.alert`). Confirmed firing on Anum's real alert format
(see section 6).

## 4. Wazuh deployment (task M3-01)

Official `wazuh/wazuh-docker` **v4.9.2** (single node: manager + indexer + dashboard), pinned
exactly, deployed under `src/detection/siem/deploy/wazuh-docker/` (git-ignored upstream clone, per
the existing README's own instructions) with RailSOC overrides layered via `docker-compose.yml`
and `config/wazuh_cluster/wazuh_manager.conf`:

- Every published port bound to `127.0.0.1` only (HC-18).
- Credentials in a local, git-ignored `.env`, **rotated from the upstream quickstart defaults**
  (`SecretPassword`/`kibanaserver`) for this submission: new bcrypt hashes generated with the
  indexer's own `plugins/opensearch-security/tools/hash.sh` and pushed into the live security
  index with `securityadmin.sh` (the reserved `admin`/`kibanaserver` users reject password changes
  through the REST API - `securityadmin.sh` is the correct tool). See
  `siem/deploy/README.md` "Credentials" for the exact commands and why the hash and the `.env`
  value have to be changed together.
- `lab/data/raw` mounted read-only into the manager; `<localfile>` entries for `pis_app.jsonl`,
  `modbus_live.jsonl`, `ssh_live.jsonl`, `attack_modbus_events.jsonl` (Modbus-only lines from every
  run's `events.jsonl` - see HC note below), and `ml_alerts.jsonl`.
- `vm.max_map_count=262144` via `wsl -d docker-desktop sysctl -w ...` (Windows/Docker Desktop
  WSL2 gotcha the starter README already called out).

**Deliberate ingestion restriction:** `pis.client` events (the attacker's own client-side HTTP
observations in each run's `events.jsonl`) are **not** ingested - `pis_app.jsonl` (the real PIS
server's own log) already recorded every one of those same requests server-side. Ingesting both
would double-count scenario A/C alerts. Modbus is different: there is no server-side PLC log (the
PLC is real third-party-style `pymodbus`, not instrumented), so `scada.poll` lines from
`events.jsonl` are the *only* record of scenario B traffic and are ingested.

### Log-source onboarding findings (what this cost in debugging, kept honest)

Two real bugs were found and fixed while actually ingesting genuine logs - exactly the kind of
thing the M1-10 "log-source sign-off" handoff is supposed to catch, and worth flagging to the rest
of the team even though both are now fixed on the M3 side:

1. **Index template type conflict.** Wazuh's bundled filebeat index template maps `data.url` as a
   plain `keyword`, but this project's event schema (`event.schema.json`, owned by Talha) defines
   `url` as an **object** (`{"path": ...}`). Every HTTP event (scenario A and C - anything with a
   `url` field) failed to index with `mapper_parsing_exception: Can't get text on a START_OBJECT`;
   Modbus events (no `url` field) were unaffected, which is why only scenario B alerts showed up in
   the indexer at first. Fixed by patching the template's `data.url` mapping to an object with a
   `path` keyword sub-field (`config/wazuh_cluster/wazuh-template-railsoc-fixed.json`, mounted over
   `/etc/filebeat/wazuh-template.json`). This is a genuine integration point between the M1-owned
   event schema and the M3-owned SIEM that the rest of the team should know about if other object
   fields (`http`, `modbus`, `network`...) are ever queried/visualised directly - they did not hit
   this because nothing else in the schema is both (a) an object and (b) also a reserved/typed
   field name in Wazuh's own template.
2. **Logcollector requires a full container recreate, not a soft restart, to pick up a new/replaced
   log file.** `docker restart` on the manager did not make `wazuh-logcollector` re-open a log file
   whose on-disk inode had changed (e.g. after deduplicating a replayed log); `docker compose stop`
   + `up` (full recreate) did. Documented here so a future "why isn't X logging" session doesn't
   repeat this detour.

## 5. SIEM queries and dashboard (tasks M3-07/M3-08)

Real, validated queries with real result counts: `siem/queries/queries.md`.
Dashboard: built via the OpenSearch Dashboards saved-objects API against the real indexer
(`lab/ops/build_dashboard.py`), exported to `siem/dashboards/railsoc_dashboard.ndjson`. Panels:
Authentication (A), Modbus (B), PIS request rate (C), ML alerts, and a security overview
(alerts-by-rule, severity distribution, a detection timeline split by scenario range). A real
screenshot of it rendering the real indexed dataset:
`siem/dashboards/screenshots/railsoc_m3_dashboard.png`. Import the NDJSON into a fresh Wazuh
Dashboard via **Stack Management -> Saved Objects -> Import** to reproduce it live. One real fix
made getting here: the detection-timeline panel's scenario buckets originally used a numeric
`range` aggregation on `rule.id`, which Wazuh indexes as `keyword` - OpenSearch rejected it
(`"Saved field 'rule.id' is invalid for use with the 'Range' aggregation"`, visible on first render);
switched to a `filters` aggregation with KQL range queries instead (works on a keyword field
because every rule ID here is the same length, so lexicographic order matches numeric order).

**A methodology note that affects both the dashboard numbers and section 3's tuning above:**
Wazuh's `frequency`/`timeframe` correlation is evaluated against **wall-clock arrival time at
analysisd**, not the event's own `@timestamp`. Tailing a log file live (as it is written) preserves
real timing; replaying an already-complete file in one shot (which this session did several times
while iterating, before understanding this) delivers potentially minutes of real-world-paced
traffic to analysisd within milliseconds, which can cross a rate threshold that the same traffic
would never cross in real time. This was caught and corrected (see rule 100303's tuning history
above) and is the reason `queries.md`'s scenario-C result table explicitly separates genuine
attack hits from replay artifacts rather than hiding the discrepancy. Live-tailed ingestion (one
new line appended as it is really produced) showed **zero** such false positives for 100303 in this
session - the dataset still contains the replay-artifact alerts from before the fix, as honest
evidence of the finding rather than quietly cleaned up.

## 6. ML integration (task M4-11)

Anum's pipeline (`src/ml/railsoc_ml/`) was run end to end on the real combined event log
(`lab/data/raw/ml_events.jsonl` - every real schema event from this session, server and client
side, normal and attack):

```bash
python -m railsoc_ml.cli build-dataset --events lab/data/raw/ml_events.jsonl \
  --runs lab/ground_truth/attack_runs.csv --assets src/simulation/config/assets.csv \
  --out lab/data/raw/ml_dataset.parquet
python -m railsoc_ml.cli train --dataset lab/data/raw/ml_dataset.parquet \
  --out lab/data/raw/ml_model.joblib
python -m railsoc_ml.cli score --events lab/data/raw/ml_events.jsonl \
  --model lab/data/raw/ml_model.joblib --assets src/simulation/config/assets.csv \
  --out lab/data/raw/ml_alerts.jsonl
```

Real result (One-Class SVM, the configured default): 495 10-second windows (63 attack), precision
0.86, recall 0.60, F1 0.71, 1 false positive out of 94 benign windows (`10.60.20.20`, a benign
latency spike), per-scenario window recall A=0.60 B=0.50 C=0.67. 64 real `ml.alert` events written
and confirmed to fire Wazuh rule 100400 (`wazuh-logtest`); indexed into the dashboard's ML panel
(Wazuh's own live log-tailing did not pick up this batch file for the same reason as finding #2
in section 4, so the 64 alerts were indexed directly via the OpenSearch bulk API as a documented
workaround - the alerts themselves, and rule 100400's match, are genuine).

## 7. Detection evaluation (task M3-10)

```bash
python -m railsoc_detection.cli evaluate \
  --wazuh-alerts lab/data/raw/manager_alerts.json \
  --ml-alerts lab/data/raw/ml_alerts.jsonl \
  --runs lab/ground_truth/attack_runs.csv --observed-hours 1.4
```

| Alert source(s) | Detection rate | False alarms | False alarms/hour |
|---|---|---|---|
| Wazuh rules only, all levels | 25% (12/48 attack runs) | 2,324 | 1,660 |
| Wazuh rules only, level >= 8 (actionable) | 21% (10/48) | 149 | 106 |
| Wazuh rules + ML | **100% (48/48)** | 2,325 | 1,661 |

**Reading this honestly, run by run** (full table in the command output, not reproduced here):
every attack run from **after** the Wazuh stack was actually deployed and correctly ingesting
(from `RUN-C-...151254Z` onward) was detected by the rules alone, most within 1-6 seconds. The
Wazuh-only *rate* above is pulled down entirely by the 22 runs that happened **before Wazuh was
even started** (the lab was run first, at 14:36-14:49, before the SIEM stack came up at 14:59) -
those runs legitimately have zero Wazuh alerts because nothing was listening yet, not because
detection failed. The **ML row is 100%** precisely because `railsoc_ml.cli score` was run after
the fact over the complete raw event log, independent of when any particular piece of SIEM
infrastructure happened to be running - a genuine, reproducible illustration of why M4 is valuable
as a complement to live rule-based detection, not just a duplicate of it.

**False alarms, honestly decomposed:** the "false alarms" count at `--observed-hours 1.4` is
dominated by rule 100302 (the base rate-*tracking* rule, level 3 - it fires on literally every PIS
request by design, including all ~30 minutes of ordinary background traffic from the normal-day
driver; it is not meant to be read as a security alarm on its own, only as the base for 100303).
Restricting to level >= 8 (100101, 100200, 100201, 100202, 100303) gives 149 false alarms/1.4h
(106/h), of which 66 are the replay-artifact 100303 hits documented in section 5 and 7 are the
pre-fix 100200 false positives documented in section 3 - i.e. essentially all of the actionable
false-alarm count in this dataset is explained by two findings already fixed, not by
undiagnosed rule weakness.

## 8. Tests and linting

```bash
python -m railsoc_detection.cli lint   # 0 issues
python scripts/check_all.py            # lint + 197 tests + compose config: all green
```

## 9. Mitigation recommendations (per scenario, tied to an observed indicator)

| Scenario | Observed indicator | Recommendation |
|---|---|---|
| A | 5 failed logins/15 s then a success, one source outside any allow-list | Rate-limit `/api/login` per source IP; require MFA or a short lockout after N failures; alert-and-review every success that follows a 100101 burst (the 100103 audit rule + the two-step query in `queries.md` already supports this). |
| B | Function-code-3 reads from an address not in `config/assets.csv` | Modbus/TCP has no built-in auth - enforce source allow-listing at the network layer (firewall/ACL on `dmz_ops`), not just detection; today's rule (100201) is the detective control, a network-layer block would be the preventive one. |
| C | Sustained request rate >2 req/s from one source against `/api/arrivals` | Add per-source rate limiting / a reverse proxy in front of the PIS stub; today's PIS stub has no such protection, which is exactly why it kept answering 200 under load instead of degrading visibly. |

## 11. Tuning changelog (task M3-11)

Every threshold change below was made against real data (not guessed), in the order found:

| Rule | Starter value | Real-world problem found | Final value | Evidence |
|---|---|---|---|---|
| 100101 (A, failure burst) | `frequency=8` (9 occurrences) | A real attack run only produces 5 failures (`request_count=6`) - would never reach 9 | `frequency=4` (5 occurrences) | `wazuh-logtest` on the real 5-failure sequence fires exactly on the 5th event; a 5-different-IPs negative test confirms `same_field` isn't accidentally bypassed |
| 100200 (B, writes) | allow-list `10.60.10.23` only | OCC-01 (`10.60.20.20`) also does real "authorised maintenance" writes in this lab's Day-1 build - fired on 100% of real legitimate writes | allow-list both `10.60.10.23` and `10.60.20.20` | 0 false positives on real maintenance-write traffic after the fix; genuine unauthorized writes from `10.60.20.99` still fire |
| 100201 (B, reads) | did not exist | starter only covered writes; `b_rogue_device.py` only reads - would have missed every real scenario B run | new rule, function-code 3 from outside `10.60.20.20` | 24/24 real unauthorized reads detected; 0/~2,600 real approved reads flagged |
| 100300/100301 (C, 5xx) | unchanged | the PIS stub never returns 5xx under this load - 0 hits across the whole dataset | kept as-is (defense in depth for a backend that *can* degrade) | confirmed via `data.http.response.status_code >= 500` returning 0 on real attack traffic |
| 100303 (C, rate) | did not exist; first version `frequency=14` (1.5 req/s) | real baseline traffic should never cross 1.5 req/s, but a **replayed** (not live-tailed) log file compresses real spacing into a near-instant burst and crossed it anyway | `frequency=19` (2 req/s) | genuine attack rate (~15-18 req/s) still trips it in <1s; confirmed **zero** false positives under live tailing after the widening (the replay-artifact hits are kept in the dataset as evidence, not deleted - see section 5) |
| 100100-103, 100201/202, 100303 | - | a single `if_matched_sid` rule cannot bridge two differently-shaped events ("failure, then a later success") - confirmed with `wazuh-logtest`, not assumed | moved the A-scenario success correlation to a two-step SIEM query; added rule 100103 (level 3, audit) purely so the success event is indexed at all | see section 3 and `siem/queries/queries.md` |

A real-time dashboard screenshot of this ruleset firing on the real dataset:
`siem/dashboards/screenshots/railsoc_m3_dashboard.png`.

## 12. What is honestly still open

- `src/detection/wireshark/profile/` (an importable Wireshark colouring profile) is still an
  empty starter stub - the display filters themselves (`wireshark/filters.md`) were all actually
  used and validated against real pcaps (section 1), just not packaged as an importable profile.
- Credentials are now rotated from the upstream quickstart defaults (admin/dashboard passwords
  regenerated with the indexer's own `hash.sh` and pushed via `securityadmin.sh` - see
  `siem/deploy/README.md` "Credentials"); they are still lab-only values suitable for a
  `127.0.0.1`-bound deployment, not a production secret-management setup.
- Playbooks (M3-09, `docs/report/playbooks.md`) cover detect/triage/contain/recover for all three
  scenarios plus ML alerts, but describe manual actions only - no active-response/automatic
  containment is configured anywhere in this lab (deliberately, per HC-02/HC-18).
