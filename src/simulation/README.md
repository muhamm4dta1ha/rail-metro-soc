# Module 1 - Simulation & Architecture

**Owner: Talha** (Simulation Lead) - **Reviewer: Roshni** (reviews every PR that touches this folder) - **Rubric:** criterion 1 (40 marks)
**Plan:** [plan/PLAN.md section 9](../../plan/PLAN.md) - tasks `M1-01` ... `M1-13`

This folder is **starter code**. **Talha** extends it task by task on `feature/sim/<TASK-ID>-<slug>` branches; **Roshni** reviews each PR. **Furqan** and **Anum** build on what this module produces, so tell them when a contract (assets, event fields) changes.

## What is here

| Path | What | Talha extends it in |
|---|---|---|
| `config/assets.csv` | Asset inventory = single source of truth for ids, IPs, zones (a contract test checks it against `docker-compose.yml`) | M1-01 |
| `config/traffic_profiles.toml` | Peak / off-peak / night-maintenance profiles and the daily schedule | M1-08 |
| `railsoc_sim/generator.py` | Deterministic generator of **normal** events (SCADA polls, PIS requests, admin logins incl. typos, authorised maintenance writes, SSH sessions) | M1-08 |
| `railsoc_sim/pis_stub.py` | PIS stub: `/api/login`, `/api/arrivals`, schema-event logging | M1-04 |
| `docker-compose.yml` | 5 isolated zones, gateway + MQTT + PIS stubs, attacker placeholder | M1-03 .. M1-09 |
| `services/` | One folder per container (`pis`, `mqtt`; add `gateway`, `station_sim`, `jumphost`, `signaling_logs`) | M1-03 .. M1-07 |
| `tests/` | Unit tests (run in CI) | every PR |

## Handoffs - who needs what from Talha

| Talha delivers | To | When |
|---|---|---|
| Lab up with PIS, jump host, station telemetry, attacker zone, `reset_lab` script, run-id hook | **Furqan** (runs the attacks on it) | end of Phase 1 |
| Log-source inventory, logs/agents ready, gateway pcaps, protocol docs | **Roshni** (ingests and analyses them) | Phases 1-2 |
| Normal-traffic generator with seeds and profiles, >= 12 simulated hours of normal data incl. benign look-alikes; asset inventory for the known-source list | **Anum** (builds the ML dataset) | Phase 2 |

## Quick start

```bash
pip install -e ".[dev]"
python -m railsoc_sim.cli assets
python -m railsoc_sim.cli generate --hours 2 --seed 1 --out lab/data/raw/normal_s1.jsonl
```

```bash
docker compose -f src/simulation/docker-compose.yml --env-file src/simulation/.env.example up --build -d
```

Generated data goes under `lab/data/` (git-ignored). The other three can develop against it from day one.

## Rules for this module (hard constraints, see plan/PLAN.md section 2)

- Everything is **synthetic and lab-only**. Never connect to operational signaling, real railway/utility networks or the internet (HC-02, HC-03).
- Station "controllers" are **monitoring-class, non-safety** devices (temperature, power feeder, lift status). Points, signals, interlocking and train protection are **not** simulated and **not** attacked.
- Lab networks stay `internal: true` and inside `10.60.0.0/16`; published ports bind to `127.0.0.1` only (HC-18).
- Every event validates against `docs/contracts/event_schema.md`; labels never go into events (HC-19).
- No secrets in git: copy `src/simulation/.env.example` to `src/simulation/.env` locally (HC-20).
- New behaviour needs tests in `src/simulation/tests/`; CI must be green before merging into `develop` (HC-14).
