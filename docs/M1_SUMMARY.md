# M1 System Simulation - quick reference (2026-11-06)

What the live lab actually does, where each piece lives, what to tweak, and what's scripted vs
manual. For the deliverable-grade write-ups see `docs/architecture/architecture.md` and
`docs/protocols/protocol_stack.md` - this page is a working cheat sheet, not a deliverable.

## What it does

Five containers in `dmz_ops`, all genuinely real (HC-23 - no fabricated log lines):

| Container | What it really is | Real protocol |
|---|---|---|
| `pis` | Python `http.server` PIS (login + arrivals) | HTTP |
| `station-plc` | Our own pymodbus TCP server; a background thread drifts 4 registers by writing to itself, like a PLC reading sensors | Modbus/TCP |
| `jumphost` | Real `openssh-server` (linuxserver.io image) | SSH |
| `occ` | Runs 3 real clients against the above (`requests`, `pymodbus`, `paramiko`) on a timer | all 3 |
| `occ-capture` | `tcpdump` sidecar, sees everything `occ` sends/receives | capture |
| `fuxa` | Real open-source SCADA/HMI, polls `station-plc` live | Modbus/TCP (reader) |

## Where in code

| Piece | File |
|---|---|
| Register map (addresses, scale factors) | `src/simulation/railsoc_sim/protocol_map.py` |
| Real PLC server + sensor drift | `src/simulation/railsoc_sim/services/station_plc.py` |
| HTTP client driver | `src/simulation/railsoc_sim/drivers/http_driver.py` |
| Modbus client driver | `src/simulation/railsoc_sim/drivers/modbus_driver.py` |
| SSH client driver | `src/simulation/railsoc_sim/drivers/ssh_driver.py` |
| Runs all 3 together | `src/simulation/railsoc_sim/scripts/run_normal_day.py` |
| Lab topology, ports, env vars | `src/simulation/docker-compose.yml` |
| Credentials (lab-only, synthetic) | `src/simulation/.env` (copy from `.env.example`, git-ignored) |
| Asset inventory (IDs, IPs, zones) | `src/simulation/config/assets.csv` |
| Bulk synthetic data for ML (NOT live traffic) | `src/simulation/railsoc_sim/generator.py` |

## What to change for different results

- **How long the live run lasts:** `.env` -> `NORMAL_DAY_DURATION` (seconds). Used today at `120` to test fast; the real run should be `1800`+ (30 min).
- **How fast the PLC's registers drift / how often maintenance writes happen:** `modbus_driver.py`'s `--poll-interval` / `--maintenance-write-every`, and `station_plc.py`'s `--drift-interval`, passed via `docker-compose.yml`'s `occ`/`station-plc` commands (not currently overridden - edit the `command:` lines there, or add more env vars like the others).
- **Which registers exist / their nominal values and scale:** `protocol_map.py`'s `METRICS` tuple and `SCALES` dict. If you add a metric here, also add a matching `Value` widget + `divisor` in FUXA's project (see below) and a row in `docs/protocols/protocol_stack.md`.
- **PIS / jump host credentials:** `.env`'s `PIS_USERS` and `JUMPHOST_PASSWORD` - synthetic only, never a real password.
- **Who the HTTP/SSH drivers log in as, typo rate, etc.:** CLI flags on each driver, set in `run_normal_day.py`'s `build_argv()`.

## Is everything scripted?

**Yes, except two one-time manual steps:**

1. **Bringing the lab up at all** is one command (from `src/simulation/`):
   ```bash
   docker compose --env-file .env build station-plc occ fuxa
   docker compose --env-file .env up -d
   ```
   Everything after that - traffic generation, capture, FUXA polling - runs on its own with no further input.

2. **FUXA's dashboard view** (`MainView`, the 5 `Value` widgets bound to the 5 tags) was built once via FUXA's own REST API (`POST /api/project`, admin login `admin`/`123456`), not through `docker-compose.yml` or a script in this repo - FUXA stores it in its own Docker volumes (`fuxa-appdata`/`fuxa-db`), so it survives container restarts but **not** a `docker compose down -v` (that deletes the volumes). If you ever need to rebuild it: log in at `/editor`, or re-run the same `POST /api/project` call (the device/tag/view JSON is in this chat's history, not currently saved as a script in the repo - worth adding as a small setup script if this needs to be reproducible later).

Everything else - drivers, the PLC server, the orchestrator, the capture - is plain code in this repo, nothing done by hand.

## Known gaps (honest, not fixed today)

- FUXA's own "Home" page (`/`) is blank - a real bug in FUXA 1.3.5, not this project. Use `/editor` (edit) or `/view?name=MainView` (live dashboard) directly.
- On Windows, a published port on an `internal: true` Docker network doesn't forward - that's why FUXA needs a temporary relay to view from the host browser (command in `docker-compose.yml`'s `fuxa` comment). Linux Docker hosts won't have this problem.
- Today's live containers are all in one zone (`dmz_ops`); the other 4 zones + inter-zone routing are still backlog (M1-03/M1-09).
