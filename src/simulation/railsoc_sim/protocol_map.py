"""Shared Modbus register map for the station controller (monitoring-only, HC-22).

Both the fast synthetic generator (``railsoc_sim.generator``, used to bulk-produce ML training
data) and the real pymodbus driver (``railsoc_sim.drivers.modbus_driver``, used for the live lab
run) read/write the same holding registers, so the two paths can never silently drift apart.
"""

from __future__ import annotations

# name, unit, nominal, spread, holding-register address (synthetic, non-safety telemetry only)
METRICS: tuple[tuple[str, str, float, float, int], ...] = (
    ("station_temp_c", "C", 22.0, 2.0, 0),
    ("feeder_voltage_v", "V", 750.0, 12.0, 1),
    ("platform_occupancy_pct", "%", 35.0, 20.0, 2),
    ("lift_available", "bool", 1.0, 0.0, 3),
)
MODBUS_PORT = 502
SETPOINT_REGISTER = 10

# Modbus holding registers are unsigned 16-bit integers, so each real-valued metric is stored as
# (python value * SCALES[name]), rounded to the nearest integer. Both the PLC program that owns
# the register and railsoc_sim.drivers.modbus_driver (which decodes it back) use this same table.
SCALES: dict[str, float] = {
    "station_temp_c": 100.0,
    "feeder_voltage_v": 10.0,
    "platform_occupancy_pct": 100.0,
    "lift_available": 1.0,
}


def encode_register(name: str, value: float) -> int:
    """Python value -> the unsigned 16-bit register word a real PLC would hold for it."""
    raw = round(value * SCALES[name])
    return max(0, min(raw, 0xFFFF))


def decode_register(name: str, raw: int) -> float:
    """The register word a real Modbus read returns -> the python value it represents."""
    return raw / SCALES[name]
