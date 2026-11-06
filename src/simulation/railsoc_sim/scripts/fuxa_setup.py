"""Builds the Metro OT mimic panel in FUXA, over its own real REST API.

FUXA (the real open-source SCADA/HMI this project uses, see docs/architecture/architecture.md)
stores its whole configuration - Modbus device, tags, and the SVG dashboard view - as one JSON
project document; there is no docker-compose equivalent or `.fuxa` file this project tracks. The
first version of this panel was built by hand, one API call at a time, in a browser console -
not reproducible. This script is that work turned into something anyone can re-run.

Running it REPLACES the live project (devices, tags, and the "MainView" dashboard) with the one
built here. If someone has since customised FUXA by hand (dragged new widgets around in the
editor), running this again will discard that - it is meant for first-time setup or for
resetting the panel back to the project's reference layout, not for day-to-day editing.

  python -m railsoc_sim.scripts.fuxa_setup --url http://127.0.0.1:1881
"""

from __future__ import annotations

import argparse
import logging
from html import escape
from typing import Any

import requests

LOGGER = logging.getLogger("railsoc_sim.scripts.fuxa_setup")

MODBUS_DEVICE_ADDRESS = "station-plc:502"
MODBUS_SLAVE_ID = "1"
TRACK_CIRCUIT_COUNT = 6

# (fuxa tag id, metric name in railsoc_sim.protocol_map, 1-based Modbus address, divisor)
# The address is the real register address (railsoc_sim.protocol_map) + 1 - FUXA numbers
# holding registers from 1, Modbus/TCP numbers them from 0.
TAGS: tuple[tuple[str, str, int, float], ...] = (
    ("tag_temp", "station_temp_c", 1, 100),
    ("tag_voltage", "feeder_voltage_v", 2, 10),
    ("tag_occupancy", "platform_occupancy_pct", 3, 100),
    ("tag_lift", "lift_available", 4, 1),
    ("tag_setpoint", "maintenance_setpoint", 11, 1),
    ("tag_feeder1_breaker", "feeder1_breaker_closed", 5, 1),
    ("tag_feeder1_current", "feeder1_current_a", 6, 10),
    ("tag_feeder2_breaker", "feeder2_breaker_closed", 7, 1),
    ("tag_feeder2_voltage", "feeder2_voltage_v", 8, 10),
    ("tag_feeder2_current", "feeder2_current_a", 9, 10),
    ("tag_zone1_fan", "zone1_fan_running", 10, 1),
    ("tag_zone1_speed", "zone1_fan_speed_pct", 12, 100),
    ("tag_zone1_temp", "zone1_temp_c", 13, 100),
    ("tag_zone2_fan", "zone2_fan_running", 14, 1),
    ("tag_zone2_speed", "zone2_fan_speed_pct", 15, 100),
    ("tag_zone2_temp", "zone2_temp_c", 16, 100),
    *(("tag_tc" + str(i), f"track_circuit_{i}_occupied", 16 + i, 1) for i in range(1, TRACK_CIRCUIT_COUNT + 1)),
)


def build_tags() -> dict[str, dict[str, Any]]:
    return {
        tag_id: {
            "id": tag_id,
            "name": name,
            "type": "UInt16",
            "memaddress": "400000",
            "address": str(address),
            "format": "0",
            "access": "readwrite" if name == "maintenance_setpoint" else "read",
            "divisor": divisor,
        }
        for tag_id, name, address, divisor in TAGS
    }


class _ViewBuilder:
    """Accumulates FUXA dashboard items + the matching inline SVG, one widget at a time."""

    def __init__(self) -> None:
        self.items: dict[str, dict[str, Any]] = {}
        self.svg_parts: list[str] = []

    def static_text(self, x: int, y: int, text: str, size: int, bold: bool = False, fill: str = "#000000") -> None:
        weight = "bold" if bold else "normal"
        self.svg_parts.append(
            f'  <text x="{x}" y="{y}" font-family="sans-serif" font-size="{size}" '
            f'font-weight="{weight}" fill="{fill}">{escape(text)}</text>'
        )

    def static_rect(self, x: int, y: int, w: int, h: int, fill: str, stroke: str = "none") -> None:
        self.svg_parts.append(f'  <rect x="{x}" y="{y}" width="{w}" height="{h}" fill="{fill}" stroke="{stroke}" stroke-width="1"/>')

    def panel_box(self, x: int, y: int, w: int, h: int) -> None:
        self.static_rect(x, y, w, h, "#fafafa", "#999999")

    def value_widget(self, item_id: str, tag_id: str, x: int, y: int, size: int, fill: str = "#0b5fff") -> None:
        self.items[item_id] = {
            "id": item_id, "type": "svg-ext-value", "name": "", "label": "Value",
            "hide": False, "lock": False, "property": {"variableId": tag_id},
        }
        self.svg_parts.append(
            f'  <g xml:space="preserve" text-anchor="start" font-family="sans-serif" font-size="{size}" '
            f'stroke="none" fill="{fill}" type="svg-ext-value" id="{item_id}">\n'
            f'   <text x="{x}" y="{y}">--</text>\n  </g>'
        )

    def indicator(self, id_prefix: str, tag_id: str, cx: int, cy: int, r: int) -> None:
        """Two overlapping circles: green when tag_id==1, red when tag_id==0."""
        green_id, red_id = f"{id_prefix}_on", f"{id_prefix}_off"
        self.items[green_id] = {
            "id": green_id, "type": "svg-ext-value", "name": "", "label": "Value", "hide": False, "lock": False,
            "property": {
                "variableId": tag_id,
                "actions": [
                    {"type": "show", "variableId": tag_id, "range": {"min": 1, "max": 1}},
                    {"type": "hide", "variableId": tag_id, "range": {"min": 0, "max": 0}},
                ],
            },
        }
        self.svg_parts.append(
            f'  <g xml:space="preserve" font-family="sans-serif" font-size="1" stroke="#333333" '
            f'stroke-width="1" fill="#2ecc71" type="svg-ext-value" id="{green_id}">\n'
            f'   <circle cx="{cx}" cy="{cy}" r="{r}"/>\n  </g>'
        )
        self.items[red_id] = {
            "id": red_id, "type": "svg-ext-value", "name": "", "label": "Value", "hide": True, "lock": False,
            "property": {
                "variableId": tag_id,
                "actions": [
                    {"type": "show", "variableId": tag_id, "range": {"min": 0, "max": 0}},
                    {"type": "hide", "variableId": tag_id, "range": {"min": 1, "max": 1}},
                ],
            },
        }
        self.svg_parts.append(
            f'  <g xml:space="preserve" font-family="sans-serif" font-size="1" stroke="#333333" '
            f'stroke-width="1" fill="#e74c3c" type="svg-ext-value" id="{red_id}">\n'
            f'   <circle cx="{cx}" cy="{cy}" r="{r}"/>\n  </g>'
        )

    def train_car(self, item_id: str, tag_id: str, x: int, y: int) -> None:
        """A train icon shown only while its track circuit is occupied (HC-22: illustrative only)."""
        self.items[item_id] = {
            "id": item_id, "type": "svg-ext-value", "name": "", "label": "Value", "hide": True, "lock": False,
            "property": {
                "variableId": tag_id,
                "actions": [
                    {"type": "show", "variableId": tag_id, "range": {"min": 1, "max": 1}},
                    {"type": "hide", "variableId": tag_id, "range": {"min": 0, "max": 0}},
                ],
            },
        }
        self.svg_parts.append(
            f'  <g xml:space="preserve" font-family="sans-serif" font-size="1" stroke="#333333" '
            f'stroke-width="1" fill="#ffcc00" type="svg-ext-value" id="{item_id}">\n'
            f'   <rect x="{x}" y="{y}" width="40" height="18" rx="5"/>\n  </g>'
        )

    def svgcontent(self) -> str:
        body = "\n".join(self.svg_parts)
        return (
            '<svg width="1024" height="768" xmlns="http://www.w3.org/2000/svg" '
            'xmlns:svg="http://www.w3.org/2000/svg" xmlns:html="http://www.w3.org/1999/xhtml">\n'
            f" <g>\n  <title>Layer 1</title>\n{body}\n </g>\n</svg>"
        )


def build_view() -> dict[str, Any]:
    v = _ViewBuilder()
    v.static_text(20, 30, "Metro OT Mimic Panel - Station A <-> Station B", 20, bold=True)

    v.panel_box(10, 50, 490, 230)
    v.static_text(20, 70, "TRACTION POWER", 15, bold=True, fill="#0b5fff")
    v.static_text(30, 105, "Feeder 1 breaker", 13)
    v.indicator("IND_f1", "tag_feeder1_breaker", 240, 101, 8)
    v.static_text(30, 135, "Feeder 1 voltage (V)", 13)
    v.value_widget("VAL_f1v", "tag_voltage", 240, 135, 13)
    v.static_text(30, 165, "Feeder 1 current (A)", 13)
    v.value_widget("VAL_f1c", "tag_feeder1_current", 240, 165, 13)
    v.static_text(30, 200, "Feeder 2 breaker", 13)
    v.indicator("IND_f2", "tag_feeder2_breaker", 240, 196, 8)
    v.static_text(30, 230, "Feeder 2 voltage (V)", 13)
    v.value_widget("VAL_f2v", "tag_feeder2_voltage", 240, 230, 13)
    v.static_text(30, 260, "Feeder 2 current (A)", 13)
    v.value_widget("VAL_f2c", "tag_feeder2_current", 240, 260, 13)

    v.panel_box(520, 50, 490, 230)
    v.static_text(530, 70, "VENTILATION / HVAC", 15, bold=True, fill="#0b5fff")
    v.static_text(540, 105, "Zone 1 (station) fan", 13)
    v.indicator("IND_z1", "tag_zone1_fan", 760, 101, 8)
    v.static_text(540, 135, "Zone 1 fan speed (%)", 13)
    v.value_widget("VAL_z1s", "tag_zone1_speed", 760, 135, 13)
    v.static_text(540, 165, "Zone 1 temp (C)", 13)
    v.value_widget("VAL_z1t", "tag_zone1_temp", 760, 165, 13)
    v.static_text(540, 200, "Zone 2 (tunnel) fan", 13)
    v.indicator("IND_z2", "tag_zone2_fan", 760, 196, 8)
    v.static_text(540, 230, "Zone 2 fan speed (%)", 13)
    v.value_widget("VAL_z2s", "tag_zone2_speed", 760, 230, 13)
    v.static_text(540, 260, "Zone 2 temp (C)", 13)
    v.value_widget("VAL_z2t", "tag_zone2_temp", 760, 260, 13)

    v.panel_box(10, 300, 490, 160)
    v.static_text(20, 320, "STATION", 15, bold=True, fill="#0b5fff")
    v.static_text(30, 350, "Platform temp (C)", 13)
    v.value_widget("VAL_temp", "tag_temp", 240, 350, 13)
    v.static_text(30, 380, "Platform occupancy (%)", 13)
    v.value_widget("VAL_occ", "tag_occupancy", 240, 380, 13)
    v.static_text(30, 410, "Lift available", 13)
    v.indicator("IND_lift", "tag_lift", 240, 406, 8)
    v.static_text(30, 445, "Maintenance setpoint (write)", 12)
    v.value_widget("VAL_setpoint", "tag_setpoint", 300, 445, 13)

    v.panel_box(10, 480, 980, 180)
    v.static_text(20, 500, "TRACK - LINE 1", 15, bold=True, fill="#0b5fff")
    v.static_rect(40, 580, 90, 36, "#cfd8dc", "#555555")
    v.static_text(85, 602, "STATION A", 11, bold=True)
    v.static_rect(890, 580, 90, 36, "#cfd8dc", "#555555")
    v.static_text(935, 602, "STATION B", 11, bold=True)
    track_x0, track_x1 = 140, 890
    seg_w = (track_x1 - track_x0) / TRACK_CIRCUIT_COUNT
    for i in range(TRACK_CIRCUIT_COUNT):
        x0 = track_x0 + i * seg_w
        v.static_rect(int(x0 + 2), 586, int(seg_w - 4), 24, "#b9c6cf", "#555555")
        v.static_text(int(x0 + seg_w / 2 - 5), 628, str(i + 1), 11, fill="#555555")
        v.train_car(f"TRAIN_{i + 1}", f"tag_tc{i + 1}", int(x0 + seg_w / 2 - 20), 582)
    v.static_text(
        260, 645, "Track-circuit occupancy is illustrative only (mimic panel) - HC-22, never real signalling.", 10,
        fill="#777777",
    )

    return {
        "id": "v_mainview",
        "name": "MainView",
        "profile": {
            "width": 1024, "height": 768, "bkcolor": "#ffffffff", "margin": 10,
            "align": "topCenter", "gridType": "fixed", "viewRenderDelay": 0,
        },
        "items": v.items,
        "variables": {},
        "svgcontent": v.svgcontent(),
        "type": "svg",
    }


def build_project() -> dict[str, Any]:
    return {
        "version": "1.00",
        "devices": {
            "dev_station_plc": {
                "id": "dev_station_plc",
                "name": "station-plc",
                "type": "ModbusTCP",
                "enabled": True,
                "polling": 2000,
                "property": {"address": MODBUS_DEVICE_ADDRESS, "slaveid": MODBUS_SLAVE_ID, "timeout": 2000},
                "tags": build_tags(),
            }
        },
        "hmi": {"views": [build_view()]},
        "recipes": [],
        "ar": {"enabled": False, "markers": []},
        "server": {"id": "0", "name": "FUXA Server", "type": "FuxaServer", "property": {}, "polling": 1000},
    }


def apply(base_url: str, username: str, password: str, *, timeout: float = 10.0) -> None:
    signin = requests.post(
        f"{base_url}/api/signin", json={"username": username, "password": password}, timeout=timeout
    )
    signin.raise_for_status()
    token = signin.json()["data"]["token"]

    response = requests.post(
        f"{base_url}/api/project",
        json=build_project(),
        headers={"x-access-token": token},
        timeout=timeout,
    )
    response.raise_for_status()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:1881", help="FUXA base URL")
    parser.add_argument("--username", default="admin", help="FUXA's own built-in default admin user")
    parser.add_argument("--password", default="123456", help="FUXA's own built-in default admin password")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    apply(args.url, args.username, args.password)
    LOGGER.info("FUXA project replaced: 1 device, %d tags, 1 view (MainView)", len(TAGS))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
