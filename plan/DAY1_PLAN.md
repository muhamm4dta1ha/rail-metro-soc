# Day 1 Plan - 2026-11-06

One day. The goal is a **small, honest, working** system that meets every requirement in [PLAN.md section 2](PLAN.md#2-hard-constraints-non-negotiable) - nothing bigger, nothing faked. Full backlog for later days is PLAN.md sections 9-12; this page is just tomorrow.

**Real protocols, always (HC-23).** HTTP, MQTT, Modbus/TCP and SSH each mean a real client talking to a real server of that protocol. No step here is "write a JSON line pretending this happened" - if a request did not really go over the network, there is no log line for it.

**If you fall behind:** drop a stretch item, never fake one. A gap you wrote down beats a result you can't actually reproduce.

## Setup (everyone, ~20 min)

- [ ] `git clone` the repo, make a venv, `pip install -e ".[dev,ml]"`
- [ ] `python scripts/check_all.py` is green
- [ ] Read your section below and your module's README (`src/<module>/README.md`)
- [ ] Branch: `git switch develop && git pull && git switch -c feature/<module>/<slug>`

---

## Talha - M1 System Simulation

You build the thing everyone else needs. Order matters: HTTP first (cheapest), then Modbus, then SSH. Stop and hand off whatever is real at Checkpoint 1 even if SSH isn't done.

1. **(15 min) Trim scope.** Keep the existing 5-zone compose (`src/simulation/docker-compose.yml`) and `assets.csv` - they already work. Decide today's minimum: PIS (HTTP), one station controller (Modbus/TCP), the jump host (SSH). MQTT is a stretch, do it last if there's time.
2. **(45 min) Real HTTP traffic.** `pis_stub.py` is already a real HTTP server. Write a small driver script (`railsoc_sim/drivers/http_driver.py`) that uses `requests` to really call `POST /api/login` and `GET /api/arrivals` against the running container, on a loop with small random delays. Confirm: a pcap taken while it runs shows real HTTP packets, and the server's own JSON logs line up with them.
3. **(90 min) Real Modbus/TCP.** Use `pymodbus`: a tiny server (`services/station_sim/`) holding a few registers (temperature, feeder voltage, occupancy, lift status - monitoring only, HC-22), and a client driver that does real function-code-3 reads on an interval and occasional function-code-6 writes (the "authorised maintenance" look-alike). The client wrapper logs a schema event (`scada.poll` / `scada.command`) right after each real call succeeds or fails - never before, never independent of it.
4. **(90 min) Real SSH.** Run an actual SSH server in the jump-host container (`openssh-server`, a fixed test keypair or password - synthetic, not a real password you use anywhere). A driver using `paramiko` really connects (and sometimes fails on purpose) on an interval; log `auth.ssh` success/failure from the driver's own connect result.
5. **(30 min) Capture.** On the gateway container, run `tcpdump`/`tshark` for the whole session, rotate every ~10 min, save under `lab/data/raw/` (git-ignored). Confirm in Wireshark: HTTP, Modbus and SSH frames are all present.
6. **(20 min) Orchestrate.** One script, `railsoc_sim/scripts/run_normal_day.py`, starts the drivers together for a fixed window (e.g. 20-30 min compressed) so Furqan/Roshni/Anum have one command to get a block of real normal traffic + matching logs.
7. **(30 min) Operations dashboard (added 2026-11-06).** `fuxa` (a real open-source SCADA/HMI, see `docker-compose.yml`) polling `station-plc` over genuine Modbus/TCP - a live view of the station's own telemetry, separate from Roshni's Wazuh *security* dashboard. Add one or two gauges/trends over the four registers; no custom code needed, it's third-party software you configure through its own web UI.
8. **Hand off at Checkpoint 1:** tell Furqan the real ports/endpoints to target; tell Roshni where the pcap and logs land; tell Anum where the JSONL logs are.
9. **(remaining time) Architecture + protocol notes.** A short `docs/architecture/architecture.md` (the zones you actually used) and a short `docs/protocols/protocol_stack.md` (HTTP/Modbus/SSH: port, what normal looks like, what an anomaly looks like) - two pages, not twelve.

**Stretch only if time remains:** MQTT (paho-mqtt client + mosquitto, already in compose), traffic-profile time-of-day shaping, `reset_lab` polish.

---

## Furqan - M2 Attack Generation

Everything you run is a real request against Talha's real services - same libraries (`requests`, `pymodbus`, `paramiko`), just used abusively and inside the existing safety harness (`ctx.guard(ip)` before every call; `src/attacks/RULES_OF_ENGAGEMENT.md`).

1. **(15 min) Sign off** `RULES_OF_ENGAGEMENT.md` and `config/lab_scope.toml` - get a thumbs-up from the other three in chat.
2. **(60 min, no dependency - start now) Scenario A, admin access.** Implement `scenarios/a_admin_access.py::execute()`: real repeated `POST /api/login` with wrong passwords (rate-capped by `ctx.params["rate_per_s"]`), then one correct login. You can build and test this against your own throwaway copy of `pis_stub.py` before Talha's lab is even up.
3. **(45 min, no dependency) Scenario C, service disruption.** Implement `scenarios/c_service_disruption.py::execute()`: a real `GET /api/arrivals` loop at a capped-but-high rate for a fixed, short duration, with the kill switch tested first (`touch .kill_attacks`, confirm it stops the loop, then remove it).
4. **After Checkpoint 1 (Talha's Modbus is real):** Scenario B, rogue device - a container/driver with its own `pymodbus` client doing unauthorised reads/writes to Talha's real station controller, from an IP that is deliberately not in `assets.csv`. If Modbus isn't ready in time, this is the one to cut, not fake.
5. **Run all three for real** against the live lab; each run through `railsoc_attacks.recorder.run_scenario(..., dry_run=False)`, which writes the manifest and the ground-truth row for you.
6. **(30 min) Baselines.** For each scenario, capture one normal-activity window of the same length with nothing attacking (`scenario_id=BASELINE` in the ground truth).
7. **Hand off:** tell Roshni the run ids/time windows and what you saw; tell Anum `lab/ground_truth/attack_runs.csv` is populated.

**Stretch only if time remains:** a 3-5 run campaign per scenario (`campaign.py`), mitigation write-up.

---

## Roshni - M3 Detection (Wireshark + SIEM)

1. **(45-60 min, no dependency - start now) Wazuh up.** `docker compose up` the official single-node Wazuh quickstart (pinned tag - record it in `src/detection/siem/deploy/README.md`). Confirm the dashboard loads.
2. **(20 min, no dependency) Wireshark ready.** Open the filters list in `src/detection/wireshark/filters.md`; have `http`, `mqtt`, `modbus`, `ssh` filters ready to paste.
3. **(15 min) Review the rule stubs** in `src/detection/siem/rules/railsoc_rules.xml` so you know what each one expects once there's real data.
4. **After Checkpoint 1 (real pcap exists):** open it in Wireshark. Protocol Hierarchy + one I/O Graph screenshot; one screenshot per protocol filter. This alone gives deliverable 5 (Wireshark evidence) something real to show.
5. **Ingest Talha's real logs** into Wazuh (agent or a simple log-forwarder on the JSONL files); confirm events show up as `data.event.dataset = pis.app / scada.poll / scada.command / auth.ssh`.
6. **After Furqan's runs exist:** validate the three rule stubs with `wazuh-logtest` against real captured lines; fix them until each fires on its run and not on the baseline. Run 2-3 saved queries per scenario (`src/detection/siem/queries/queries.md`), screenshot the results.
7. **(60 min) One simple dashboard:** alerts-over-time panel, one panel per scenario, one panel for `ml.alert` once Anum has alerts. Export it (`*.ndjson`).
8. **End of day:** run `python -m railsoc_detection.cli evaluate ...` against your exported alerts and Furqan's ground truth; paste the table into `docs/report/evaluation.md`.

**Stretch only if time remains:** playbooks (`docs/report/playbooks.md`), threshold tuning.

---

## Anum - M4 ML

Good news: `features.py`, `dataset.py`, `models.py`, `evaluate.py`, `serve.py` and the CLI already exist and pass their tests. Today's job is mostly pointing them at **real** data and checking the result honestly, not building from scratch.

1. **(20 min, no dependency) Confirm the pipeline still works**: `python -m railsoc_ml.cli build-dataset / train / score` on a tiny hand-made sample (the existing tests already do this - just re-run `pytest src/ml/tests -q`).
2. **(20 min) Read `src/ml/railsoc_ml/features.py`** and note anything that assumes JSON-only "pretend" events; flag it to Talha if a feature needs a field his real drivers don't log yet.
3. **After Checkpoint 1 (Talha's normal data exists):** `railsoc_ml.cli build-dataset` on the real JSONL logs with no attacks yet - sanity check the feature distributions look sane (not all zeros, not all identical).
4. **After Furqan's runs exist (ground truth has real rows):** rebuild the dataset including the attack windows, `train` (One-Class SVM default), check the printed metrics honestly - recall, false-alarm rate. If recall is bad on one scenario, say so; do not retune until the test set silently disappears.
5. **(30 min) `score`** the full day's log file to produce `ml.alert` events; hand the file to Roshni for the dashboard panel and for `railsoc_detection.evaluate`.
6. **End of day:** three honest sentences in `src/ml/reports/results.md` - what was trained on, what the metrics were, what definitely needs more data (there won't be much today).

**Stretch only if time remains:** the random-forest supervised model, a model card.

---

## End of day (everyone, ~20 min)

- [ ] Each person's branch -> PR into `develop` (small, reviewed by the ring in PLAN.md section 3.1)
- [ ] 10-minute sync: what's real and working, what's a logged gap - update `context/02_CURRENT_STATE.md` (Talha)
- [ ] Nothing in the report or the demo claims something ran that didn't actually run
