# M1 System Simulation - quick reference (2026-11-06)

What the live lab actually does, where each piece lives, what to tweak, and what's scripted vs
manual. For the deliverable-grade write-ups see `docs/architecture/architecture.md` and
`docs/protocols/protocol_stack.md` - this page is a working cheat sheet, not a deliverable.

## What it does

Six containers in `dmz_ops`, all genuinely real (HC-23 - no fabricated log lines):

| Container | What it really is | Real protocol |
|---|---|---|
| `pis` | Python `http.server` PIS (login + arrivals) | HTTP |
| `station-plc` | Our own pymodbus TCP server modelling a metro OT plant: traction power, HVAC and track-circuit occupancy - two background threads drift the analogue points and shuttle a "train" between two stations, by writing to itself like a real PLC reads sensors | Modbus/TCP |
| `jumphost` | Real `openssh-server` (linuxserver.io image) | SSH |
| `occ` | Runs 3 real clients against the above (`requests`, `pymodbus`, `paramiko`) on a timer | all 3 |
| `occ-capture` | `tcpdump` sidecar, sees everything `occ` sends/receives | capture |
| `fuxa` | Real open-source SCADA/HMI - a mimic panel (traction power, HVAC, a 6-segment track with a moving train icon), polling `station-plc` live | Modbus/TCP (reader) |

## Where in code

| Piece | File |
|---|---|
| Register map (addresses, scale factors, which points are which subsystem) | `src/simulation/railsoc_sim/protocol_map.py` |
| Real PLC server, sensor drift, train movement | `src/simulation/railsoc_sim/services/station_plc.py` |
| HTTP client driver | `src/simulation/railsoc_sim/drivers/http_driver.py` |
| Modbus client driver | `src/simulation/railsoc_sim/drivers/modbus_driver.py` |
| SSH client driver | `src/simulation/railsoc_sim/drivers/ssh_driver.py` |
| Runs all 3 together | `src/simulation/railsoc_sim/scripts/run_normal_day.py` |
| **Builds the FUXA mimic panel** (device, 22 tags, the view) | `src/simulation/railsoc_sim/scripts/fuxa_setup.py` |
| Lab topology, ports, env vars | `src/simulation/docker-compose.yml` |
| Credentials (lab-only, synthetic) | `src/simulation/.env` (copy from `.env.example`, git-ignored) |
| Asset inventory (IDs, IPs, zones) | `src/simulation/config/assets.csv` |
| Bulk synthetic data for ML (NOT live traffic) | `src/simulation/railsoc_sim/generator.py` |

## The OT model (what the mimic panel shows)

| Subsystem | Points | Addresses |
|---|---|---|
| Station | platform temp, platform occupancy, lift available, maintenance setpoint (writable) | 0, 2, 3, 10 |
| Traction power | 2 feeder breakers (open/closed), each with voltage + current | 1, 4-8 |
| Ventilation/HVAC | 2 zones (station, tunnel), each fan running + speed + temp | 9, 11-15 |
| Track circuits | 6 segments, Station A and B at the ends - **illustrative only, HC-22 amendment 2026-11-06** | 16-21 |

`station_plc.py` runs two background threads: `drift_forever` (random-walk on every analogue
point) and `train_forever` (shuttles exactly one track circuit's `_occupied` flag between the two
ends, with a longer dwell at each station). Breakers and fans stay fixed (closed/running) today -
scripting a trip/cycle schedule for them is a natural next step, not done yet.

## What to change for different results

- **How long the live run lasts:** `.env` -> `NORMAL_DAY_DURATION` (seconds). Used today at `120` to test fast; the real run should be `1800`+ (30 min).
- **How fast things drift/move:** `modbus_driver.py`'s `--poll-interval` / `--maintenance-write-every`; `station_plc.py`'s `--drift-interval`, `--train-move-interval`, `--train-dwell-interval` - passed via `docker-compose.yml`'s `occ`/`station-plc` `command:` (not currently overridden there; edit those lines or add env vars like the others).
- **Which points exist, their subsystem, nominal values and scale:** `protocol_map.py`'s `METRICS` / `TRACTION_POINTS` / `HVAC_POINTS` / `TRACK_CIRCUITS` tuples and the `SCALES` dict. Add a point here, then add a matching tag + widget in `fuxa_setup.py` and re-run it, and add a row to `docs/protocols/protocol_stack.md`.
- **The mimic panel's layout, colours, what's on it:** `fuxa_setup.py`'s `build_view()` - it's plain Python building SVG strings, not a drag-and-drop file; re-run the script after editing it.
- **PIS / jump host credentials:** `.env`'s `PIS_USERS` and `JUMPHOST_PASSWORD` - synthetic only, never a real password.
- **Who the HTTP/SSH drivers log in as, typo rate, etc.:** CLI flags on each driver, set in `run_normal_day.py`'s `build_argv()`.

## Is everything scripted?

**Yes.** One command brings the lab up (from `src/simulation/`):
```bash
docker compose --env-file .env build station-plc occ fuxa
docker compose --env-file .env up -d
```
and a second builds (or rebuilds) the FUXA mimic panel - device, all 22 tags, and the `MainView`
dashboard - against the running `fuxa`:
```bash
python -m railsoc_sim.scripts.fuxa_setup --url http://127.0.0.1:1881
```
(On Windows you'll need the port-forward relay below running first so `127.0.0.1:1881` reaches
it; inside the Docker network, e.g. from another container, use `http://fuxa:1881` directly.)
Re-running `fuxa_setup.py` **replaces** the live project - fine for first-time setup or resetting
back to the reference panel, but it discards any by-hand edits made in FUXA's own editor since.

Everything else - drivers, the PLC server, the orchestrator, the capture - is plain code in this
repo. Nothing is a one-off browser-console action any more.

## Known gaps (honest, not fixed today)

- FUXA's own "Home" page (`/`) is blank - a real bug in FUXA 1.3.5, not this project. Use `/editor` (edit) or `/view?name=MainView` (live dashboard) directly.
- On Windows, a published port on an `internal: true` Docker network doesn't forward - that's why FUXA needs a temporary relay to view from the host browser (command in `docker-compose.yml`'s `fuxa` comment). Linux Docker hosts won't have this problem.
- Today's live containers are all in one zone (`dmz_ops`); the other 4 zones + inter-zone routing are still backlog (M1-03/M1-09).
- Breaker trips and fan on/off cycling aren't scripted yet - both points exist and are polled for real, they just don't change today.
