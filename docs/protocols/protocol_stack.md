# Protocol stack - today's real traffic (2026-11-06)

Two pages, not twelve. This replaces the starter table with what is actually wired up and real
today; the railway-signalling context (GSM-R/FRMCS, CBTC, EN 50159) that is **described, never
simulated** stays as in the original starter table below.

## HTTP - Passenger Information System

| | |
|---|---|
| Port | TCP 8080 (`pis`, 10.60.20.10) |
| Real client | `railsoc_sim.drivers.http_driver` (`requests`), running inside `occ` |
| Real server | `railsoc_sim.pis_stub` (`http.server`) - unchanged, already real |
| Normal | `GET /api/arrivals` most of the time; occasional `POST /api/login` with the right password; a configurable rate of deliberate typos (wrong password, still the right account) |
| Anomaly | a burst of `401` from one source (Furqan's scenario A); a flood of `GET` (scenario C) |
| Who logs | the server, in the same request handler that answered the real request - never the client |

## Modbus/TCP - station controller telemetry

| | |
|---|---|
| Port | TCP 502 (`station-plc`, 10.60.20.22) |
| Real client | `railsoc_sim.drivers.modbus_driver` (`pymodbus`), running inside `occ` |
| Real server | `railsoc_sim.services.station_plc` (`station-plc`) - a real pymodbus TCP server we wrote, monitoring-only registers (HC-22: no points/signals/interlocking); OpenPLC was today's first choice but took too long to compile, see docs/architecture/architecture.md |
| Register map | `railsoc_sim/protocol_map.py` - registers 0-3 (station: temperature, feeder 1 voltage, platform occupancy, lift status), 4-8 (traction power: two feeder breakers + currents/voltage), 9/11-15 (ventilation: two HVAC zones, fan state/speed/temp), 16-21 (six track-circuit occupancy flags, illustrative only - HC-22 amendment), register 10 (maintenance setpoint, writable) |
| Encoding | registers are unsigned 16-bit words; `encode_register`/`decode_register` apply a fixed scale per metric (e.g. `x100` for `station_temp_c`) since Modbus has no native float |
| Normal | function code 3 (read) on a fixed interval; occasional function code 6 (write) to the setpoint register - an "authorised maintenance" look-alike |
| Anomaly | writes from a source that never does maintenance (Furqan's scenario B, deliberately not in `assets.csv`) |
| Who logs | the client (`modbus_driver`), right after each real call returns - `station_plc.py` is a bare protocol server with no event schema of its own, so the client is the only side that can log |

## SSH - jump host

| | |
|---|---|
| Port | TCP 2222 on `jumphost` (linuxserver/openssh-server's fixed internal port; still `auth.ssh`/port-22-shaped in the event data) |
| Real client | `railsoc_sim.drivers.ssh_driver` (`paramiko`) |
| Real server | `lscr.io/linuxserver/openssh-server`, user `eng_maint`, password auth (synthetic lab password, `$JUMPHOST_PASSWORD`) |
| Normal | a real connect + authenticate on an interval; a configurable rate of deliberate typos (benign failures) |
| Anomaly | repeated failures with no eventual success; connections at odd hours |
| Who logs | the client, from its own real connect result - the stock sshd image does not speak our schema either |
| Known gap | host keys are auto-accepted (`AutoAddPolicy`); fine for an isolated synthetic lab (HC-18), never for anything real |

## MQTT, NTP/DNS, and the railway-signalling context

Not wired up today (stretch - see `plan/DAY1_PLAN.md`). The broker (`mqtt-broker`, real
`eclipse-mosquitto`) is already running and unchanged from the starter; no driver publishes to it
yet.

Described, **never simulated or attacked** (HC-01, HC-02, HC-22): GSM-R/FRMCS and CBTC radio
links, and any safety signalling protocol. Use the EN 50159 threat categories - corruption,
repetition, deletion, insertion, resequencing, delay, masquerade - as the vocabulary for "what
could go wrong" in that description, and map each to a detection signal in the report.

## Wireshark capture

`occ-capture` (a `nicolaka/netshoot` sidecar sharing the `occ` container's network namespace)
captures every real packet `occ` sends or receives - HTTP, Modbus and SSH all in one pcap, since
all three real clients run inside that one container. Files land in `lab/data/raw/pcap/*.pcap`
(git-ignored), rotated every 10 minutes. Open in Wireshark and filter `http`, `modbus` or `ssh` to
verify each protocol independently; Protocol Hierarchy should show real traffic on all three,
never a flat line with everything claimed in the JSONL logs but nothing on the wire.
