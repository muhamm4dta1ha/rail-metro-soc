"""Shared Modbus register map for the station controller.

HC-22 (amended 2026-11-06, see plan/PLAN.md): every point here is monitoring-class telemetry,
including the track-circuit occupancy booleans added for the mimic panel - they drive no logic,
enforce no separation, compute no movement authority, and are never an attack target. Real
interlocking, signalling logic and train protection are still never simulated.

Both the fast synthetic generator (``railsoc_sim.generator``, used to bulk-produce ML training
data) and the real pymodbus driver/server (``railsoc_sim.drivers.modbus_driver``,
``railsoc_sim.services.station_plc``, used for the live lab run) read/write the same holding
registers, so the paths can never silently drift apart.
"""

from __future__ import annotations

Point = tuple[str, str, float, float, int]

# name, unit, nominal, spread, holding-register address.
# "spread" is the random-walk amplitude a background thread drifts analog points by; state
# points (booleans) use spread 0.0 and are instead driven by explicit simulation logic (train
# position, breaker/fan schedule) - see railsoc_sim.services.station_plc.
METRICS: tuple[Point, ...] = (
    ("station_temp_c", "C", 22.0, 2.0, 0),
    ("feeder_voltage_v", "V", 750.0, 12.0, 1),
    ("platform_occupancy_pct", "%", 35.0, 20.0, 2),
    ("lift_available", "bool", 1.0, 0.0, 3),
)

# Traction power: two feeder breakers, each with its own current (and a second voltage) -
# monitoring only, nothing here commands or protects anything real.
TRACTION_POINTS: tuple[Point, ...] = (
    ("feeder1_breaker_closed", "bool", 1.0, 0.0, 4),
    ("feeder1_current_a", "A", 420.0, 30.0, 5),
    ("feeder2_breaker_closed", "bool", 1.0, 0.0, 6),
    ("feeder2_voltage_v", "V", 748.0, 12.0, 7),
    ("feeder2_current_a", "A", 410.0, 30.0, 8),
)

# Ventilation/HVAC: two zones (station platform, tunnel).
HVAC_POINTS: tuple[Point, ...] = (
    ("zone1_fan_running", "bool", 1.0, 0.0, 9),
    ("zone1_fan_speed_pct", "%", 70.0, 8.0, 11),
    ("zone1_temp_c", "C", 24.0, 2.0, 12),
    ("zone2_fan_running", "bool", 1.0, 0.0, 13),
    ("zone2_fan_speed_pct", "%", 65.0, 8.0, 14),
    ("zone2_temp_c", "C", 23.0, 2.0, 15),
)

# Track-circuit occupancy (HC-22 amendment): illustrative only, drives the mimic panel's train
# icon. TC1 = Station A platform, TC2-TC5 = the line between the two stations, TC6 = Station B
# platform. railsoc_sim.services.station_plc moves exactly one of these at a time.
TRACK_CIRCUITS: tuple[Point, ...] = (
    ("track_circuit_1_occupied", "bool", 0.0, 0.0, 16),
    ("track_circuit_2_occupied", "bool", 0.0, 0.0, 17),
    ("track_circuit_3_occupied", "bool", 0.0, 0.0, 18),
    ("track_circuit_4_occupied", "bool", 0.0, 0.0, 19),
    ("track_circuit_5_occupied", "bool", 0.0, 0.0, 20),
    ("track_circuit_6_occupied", "bool", 0.0, 0.0, 21),
)

# Every monitoring point on the PLC - what the real client driver (modbus_driver.py) polls.
ALL_POINTS: tuple[Point, ...] = METRICS + TRACTION_POINTS + HVAC_POINTS + TRACK_CIRCUITS

# Points whose value is a boolean state driven by explicit simulation logic (train position,
# breaker/fan schedule) rather than analog drift.
STATE_POINT_NAMES: frozenset[str] = frozenset(
    {"lift_available", "feeder1_breaker_closed", "feeder2_breaker_closed"}
    | {"zone1_fan_running", "zone2_fan_running"}
    | {name for name, *_rest in TRACK_CIRCUITS}
)

MODBUS_PORT = 502
SETPOINT_REGISTER = 10

# Modbus holding registers are unsigned 16-bit integers, so each real-valued point is stored as
# (python value * SCALES[name]), rounded to the nearest integer. Both the PLC program that owns
# the register and railsoc_sim.drivers.modbus_driver (which decodes it back) use this same table.
SCALES: dict[str, float] = {
    "station_temp_c": 100.0,
    "feeder_voltage_v": 10.0,
    "platform_occupancy_pct": 100.0,
    "lift_available": 1.0,
    "feeder1_breaker_closed": 1.0,
    "feeder1_current_a": 10.0,
    "feeder2_breaker_closed": 1.0,
    "feeder2_voltage_v": 10.0,
    "feeder2_current_a": 10.0,
    "zone1_fan_running": 1.0,
    "zone1_fan_speed_pct": 100.0,
    "zone1_temp_c": 100.0,
    "zone2_fan_running": 1.0,
    "zone2_fan_speed_pct": 100.0,
    "zone2_temp_c": 100.0,
    "track_circuit_1_occupied": 1.0,
    "track_circuit_2_occupied": 1.0,
    "track_circuit_3_occupied": 1.0,
    "track_circuit_4_occupied": 1.0,
    "track_circuit_5_occupied": 1.0,
    "track_circuit_6_occupied": 1.0,
}


def encode_register(name: str, value: float) -> int:
    """Python value -> the unsigned 16-bit register word a real PLC would hold for it."""
    raw = round(value * SCALES[name])
    return max(0, min(raw, 0xFFFF))


def decode_register(name: str, raw: int) -> float:
    """The register word a real Modbus read returns -> the python value it represents."""
    return raw / SCALES[name]
