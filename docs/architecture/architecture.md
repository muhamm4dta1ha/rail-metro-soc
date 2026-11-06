# Architecture - what is actually running today (2026-11-06)

Two pages, not twelve. For the full six-week target architecture (five zones, a routing gateway,
four station controllers) see `plan/PLAN.md` section 4 and `config/assets.csv`; this page is the
honest, scoped-down version that is actually live in `docker-compose.yml` today.

## What is simulated vs. only described

| Layer | Today | Backlog |
|---|---|---|
| HTTP (PIS) | Real `http.server`-based server + real `requests` client traffic | time-of-day shaping, MQTT display feed |
| Modbus/TCP (station controller) | Real `pymodbus`-based server modelling traction power, HVAC and track-circuit occupancy (see below) + real `pymodbus` client | 4 separate controllers across `station_field`, real interlocking/signalling equipment (never simulated at all - HC-22) |
| SSH (jump host) | Real `openssh-server` + real `paramiko` client | key-based auth, parsing the real sshd log instead of the driver's own result |
| Inter-zone routing (gateway) | Placeholder only (M1-03/M1-09) | a real router container forwarding between all 5 zones |
| Railway signalling, CBTC, GSM-R/FRMCS, train protection | **Never simulated or attacked** (HC-01, HC-02, HC-22) | described only, see `docs/protocols/protocol_stack.md` |

## Today's topology (one zone, on purpose)

The target design is five isolated `10.60.0.0/16` zones joined by a routing `gateway` container.
That gateway is still a placeholder (`M1-03`/`M1-09` are backlog), so routing packets between two
different zones does not work yet. Rather than fake cross-zone traffic, every live container
today sits in **`dmz_ops`** - the zone `pis` already lived in - so every protocol exchange is a
real, physically-possible packet on one Docker bridge network, not a pretended multi-hop path.

```
dmz_ops (10.60.20.0/24, internal: true)
  pis          10.60.20.10   real HTTP server (pis_stub.py)             PIS-01
  mqtt-broker  10.60.20.11   real mosquitto (unused by today's drivers) MQTT-01
  occ          10.60.20.20   real HTTP/Modbus/SSH *client* drivers      OCC-01 (+ WS-03's role today)
  station-plc  10.60.20.22   real pymodbus server (station_plc.py)     PLC-01
  fuxa         10.60.20.23   real open-source SCADA/HMI dashboard       HMI-01
  jumphost     10.60.20.30   real sshd (linuxserver/openssh-server)     JH-01
  gateway      10.60.20.254  present on every zone, not yet routing     GW-DMZ
```

`occ` is one container that plays two roles for today only: OCC-01's poller (`scada.poll`) and
maintenance-writer (`scada.command`), and WS-03's SSH client (`auth.ssh`). Splitting those onto
their own hosts, and re-introducing `corporate_it` / `station_field` / `attacker_lab` once the
gateway actually routes, is explicit backlog - see `plan/DAY1_PLAN.md` and `context/03_NEXT_STEPS.md`.

Every real packet the `occ` driver sends or receives crosses that one container's interface, so
the `occ-capture` sidecar (a `nicolaka/netshoot` container sharing `occ`'s network namespace)
is today's single Wireshark capture point - see `docs/protocols/protocol_stack.md`.

## Why FUXA, and why station-plc is our own code after all (HC-23: real protocols, nothing assumed)

Searching for an existing open-source "metro simulator" to reuse came up empty - none exists at
the fidelity this project needs. There is a real precedent for the one piece that would have
mattered most (the PLC): **Open-SecUTS**, a published metro-SCADA security testbed, rebuilds its
PLC on **OpenPLC** (Taming the War in Memory, arXiv:1809.07477) - a real, independently-developed
PLC runtime (https://github.com/thiagoralves/OpenPLC_v3). That was today's first choice too, but
OpenPLC has no prebuilt image worth trusting unmodified, and compiling it from its own Dockerfile
(a full C/C++ build: MatIEC, the runtime engine, its Python webserver) took longer than a one-day
build has room for. **`station-plc` is therefore our own code**
(`railsoc_sim.services.station_plc`) - still a completely real pymodbus TCP server with genuine
function-code 3/6 handling and a real background "sensor input" loop (a second real client
writing to itself on an interval, the way a real PLC updates its registers from physical
sensors) - just not independent third-party software. The honest label for this in the report is
"a real protocol server we wrote," not "a real PLC we reused."

`fuxa` (https://github.com/frangoteam/FUXA) **is** reused as-is: a real, independent, open-source
web SCADA/HMI package that polls `station-plc` over genuine Modbus/TCP. Nothing in the dashboard
is pushed or faked by our own code - FUXA reads the same registers any real Modbus client would.

**Known gap - published ports on Windows.** `fuxa` publishes `127.0.0.1:1881` in `docker-compose.yml`, which is correct and will work on a Linux Docker host, but on Docker Desktop for Windows a published port on an `internal: true` network (every lab zone, per HC-18) silently doesn't forward - confirmed with a plain `nginx` container on the same network, so it is a platform limitation, not a mistake in this file. The workaround (a temporary relay container attached to both `dmz_ops` and the host, never committed to this repo) is in the compose file's comment above the `fuxa` service. **This will affect Roshni's Wazuh dashboard too** (`soc_mgmt` is `internal: true` the same way) - same workaround applies.

**Known gap - FUXA's own "Home" page.** FUXA 1.3.5's Home screen (the page you land on at `/`) has a real front-end bug - its side-nav drawer opens with zero width and the page stays blank, reproducible in a clean browser, not specific to this setup. It does not affect the dashboard itself: open `/view?name=MainView` directly for the live runtime view (real, continuously-updating data - confirmed by watching values change between page loads), or `/editor` to edit it (renders correctly).

**The dashboard itself: a mimic panel, not a list of numbers.** `MainView` groups the PLC's points
into the sections a real metro OT mimic panel would have - **Traction Power** (two feeder
breakers, each with voltage/current), **Ventilation/HVAC** (two zones, fan state/speed/temp), a
**Station** panel (the original four points), and a **Track - Line 1** diagram with two station
boxes and six track-circuit segments. A breaker/fan's state is two overlapping coloured circles
(green/red) that FUXA shows or hides via its own `property.actions` (`show`/`hide` with a value
range) bound to the boolean tag - there is no dedicated "lamp" widget in this FUXA build, so every
coloured indicator and the train icon reuse the plain `Value` widget type, just with an empty/tiny
text child so nothing numeric is visible. The **train** is the same trick repeated six times: one
icon per track circuit, each shown only while its circuit's `..._occupied` tag is `1` - as
`railsoc_sim.services.station_plc`'s `train_forever()` thread shuttles that flag from circuit to
circuit, exactly one icon is visible at a time, giving the appearance of one train moving along
the line. **HC-22 (amended 2026-11-06):** every track-circuit tag is illustrative, monitoring-class
telemetry only - nothing here computes or enforces anything, and none of it is a valid attack
target; see `plan/PLAN.md`.

Every tag has a `divisor` (`100` for `_c`/`_pct` points, `10` for currents/voltages, `1` for
booleans) so FUXA shows the real engineering value, not the raw 16-bit register word. Login for
the editor: `admin` / `123456` (FUXA's own built-in default - change it under Users once this
moves past a one-day lab). **This whole project (device, 22 tags, the view) is reproducible with
one command** - `python -m railsoc_sim.scripts.fuxa_setup` - instead of the one-off browser-console
session that first built it; see `docs/M1_SUMMARY.md`.

The previous starter generator (`railsoc_sim/generator.py`) is kept, but only for its original,
honest purpose: producing bulk *synthetic* training data for Anum's ML pipeline quickly. It is
never used as a stand-in for captured lab evidence (HC-23); see `plan/PLAN.md` HC-23 and
`context/04_CHANGELOG.md`.
