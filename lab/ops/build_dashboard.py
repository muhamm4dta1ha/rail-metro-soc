"""Builds the M3 SOC dashboard (panels + visualizations) via the OpenSearch Dashboards
saved_objects API, against the real wazuh-alerts index. Run once Wazuh is up:

  python lab/ops/build_dashboard.py

Exports the result to src/detection/siem/dashboards/railsoc_dashboard.ndjson afterward via
`python lab/ops/build_dashboard.py --export`.
"""
from __future__ import annotations

import json
import ssl
import sys
import urllib.request

BASE = "https://localhost:443"
AUTH = ("admin", "SecretPassword")
INDEX_PATTERN_ID = "wazuh-alerts-railsoc"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def call(method, path, body=None):
    url = BASE + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("osd-xsrf", "true")
    req.add_header("Content-Type", "application/json")
    import base64

    token = base64.b64encode(f"{AUTH[0]}:{AUTH[1]}".encode()).decode()
    req.add_header("Authorization", f"Basic {token}")
    with urllib.request.urlopen(req, context=CTX) as resp:
        return json.loads(resp.read().decode())


def search_source(filters=None):
    return json.dumps(
        {
            "index": INDEX_PATTERN_ID,
            "query": {"query": "", "language": "kuery"},
            "filter": filters or [],
        }
    )


def make_vis(obj_id, title, vis_state, filters=None):
    body = {
        "attributes": {
            "title": title,
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "description": "",
            "kibanaSavedObjectMeta": {"searchSourceJSON": search_source(filters)},
        },
        "references": [
            {
                "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                "type": "index-pattern",
                "id": INDEX_PATTERN_ID,
            }
        ],
    }
    return call("POST", f"/api/saved_objects/visualization/{obj_id}?overwrite=true", body)


VISUALIZATIONS = [
    # Panel 1: Authentication monitoring (scenario A)
    (
        "railsoc_vis_auth_timeline",
        "Auth: failures / bursts / successes over time",
        {
            "title": "Auth: failures / bursts / successes over time",
            "type": "histogram",
            "params": {"grid": {}, "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom", "scale": {"type": "linear"}, "labels": {"show": True}, "title": {}}], "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left", "scale": {"type": "linear", "mode": "normal"}, "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100}, "title": {"text": "Count"}}], "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked", "data": {"label": "Count", "id": "1"}, "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True, "showCircles": True}], "addTooltip": True, "addLegend": True, "legendPosition": "right", "times": [], "addTimeMarker": False},
            "aggs": [
                {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
                {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment", "params": {"field": "timestamp", "interval": "auto", "min_doc_count": 1}},
                {"id": "3", "enabled": True, "type": "terms", "schema": "group", "params": {"field": "rule.id", "size": 5, "order": "desc", "orderBy": "1"}},
            ],
        },
        [{"meta": {"alias": None, "disabled": False, "negate": False}, "query": {"terms": {"rule.id": ["100100", "100101", "100103"]}}}],
    ),
    (
        "railsoc_vis_auth_sources",
        "Auth: top source IPs (failures + bursts)",
        {
            "title": "Auth: top source IPs (failures + bursts)",
            "type": "table",
            "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False, "showTotal": True, "totalFunc": "sum"},
            "aggs": [
                {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
                {"id": "2", "enabled": True, "type": "terms", "schema": "bucket", "params": {"field": "data.source.ip", "size": 10, "order": "desc", "orderBy": "1"}},
                {"id": "3", "enabled": True, "type": "terms", "schema": "bucket", "params": {"field": "rule.id", "size": 5, "order": "desc", "orderBy": "1"}},
            ],
        },
        [{"meta": {"alias": None, "disabled": False, "negate": False}, "query": {"terms": {"rule.id": ["100100", "100101"]}}}],
    ),
    # Panel 2: Modbus monitoring (scenario B)
    (
        "railsoc_vis_modbus_sources",
        "Modbus: unauthorized read sources",
        {
            "title": "Modbus: unauthorized read sources",
            "type": "table",
            "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False, "showTotal": True, "totalFunc": "sum"},
            "aggs": [
                {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
                {"id": "2", "enabled": True, "type": "terms", "schema": "bucket", "params": {"field": "data.source.ip", "size": 10, "order": "desc", "orderBy": "1"}},
            ],
        },
        [{"meta": {"alias": None, "disabled": False, "negate": False}, "query": {"terms": {"rule.id": ["100200", "100201", "100202"]}}}],
    ),
    (
        "railsoc_vis_modbus_rules",
        "Modbus: rule breakdown (write vs unauthorized read)",
        {
            "title": "Modbus: rule breakdown (write vs unauthorized read)",
            "type": "pie",
            "params": {"addTooltip": True, "addLegend": True, "legendPosition": "right", "isDonut": True},
            "aggs": [
                {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
                {"id": "2", "enabled": True, "type": "terms", "schema": "segment", "params": {"field": "rule.description", "size": 5, "order": "desc", "orderBy": "1"}},
            ],
        },
        [{"meta": {"alias": None, "disabled": False, "negate": False}, "query": {"terms": {"rule.id": ["100200", "100201", "100202"]}}}],
    ),
    # Panel 3: Passenger Information System monitoring (scenario C)
    (
        "railsoc_vis_pis_rate_timeline",
        "PIS: request rate by source over time",
        {
            "title": "PIS: request rate by source over time",
            "type": "histogram",
            "params": {"grid": {}, "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom", "scale": {"type": "linear"}, "labels": {"show": True}, "title": {}}], "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left", "scale": {"type": "linear", "mode": "normal"}, "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100}, "title": {"text": "Count"}}], "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked", "data": {"label": "Count", "id": "1"}, "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True, "showCircles": True}], "addTooltip": True, "addLegend": True, "legendPosition": "right", "times": [], "addTimeMarker": False},
            "aggs": [
                {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
                {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment", "params": {"field": "timestamp", "interval": "auto", "min_doc_count": 1}},
                {"id": "3", "enabled": True, "type": "terms", "schema": "group", "params": {"field": "data.source.ip", "size": 5, "order": "desc", "orderBy": "1"}},
            ],
        },
        [{"meta": {"alias": None, "disabled": False, "negate": False}, "query": {"terms": {"rule.id": ["100302", "100303"]}}}],
    ),
    (
        "railsoc_vis_pis_abnormal_rate",
        "PIS: abnormal-rate alerts only (rule 100303)",
        {
            "title": "PIS: abnormal-rate alerts only (rule 100303)",
            "type": "table",
            "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False, "showTotal": True, "totalFunc": "sum"},
            "aggs": [
                {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
                {"id": "2", "enabled": True, "type": "terms", "schema": "bucket", "params": {"field": "data.source.ip", "size": 10, "order": "desc", "orderBy": "1"}},
            ],
        },
        [{"meta": {"alias": None, "disabled": False, "negate": False}, "query": {"term": {"rule.id": "100303"}}}],
    ),
    # Panel 4: ML alerts
    (
        "railsoc_vis_ml_alerts",
        "ML alerts (rule 100400-100499)",
        {
            "title": "ML alerts (rule 100400-100499)",
            "type": "table",
            "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False, "showTotal": True, "totalFunc": "sum"},
            "aggs": [
                {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
                {"id": "2", "enabled": True, "type": "terms", "schema": "bucket", "params": {"field": "rule.description", "size": 10, "order": "desc", "orderBy": "1"}},
            ],
        },
        [{"meta": {"alias": None, "disabled": False, "negate": False}, "query": {"range": {"rule.id": {"gte": "100400", "lte": "100499"}}}}],
    ),
    # Panel 5: Security overview
    (
        "railsoc_vis_overview_by_rule",
        "Overview: total alerts by rule",
        {
            "title": "Overview: total alerts by rule",
            "type": "table",
            "params": {"perPage": 20, "showPartialRows": False, "showMetricsAtAllLevels": False, "showTotal": True, "totalFunc": "sum"},
            "aggs": [
                {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
                {"id": "2", "enabled": True, "type": "terms", "schema": "bucket", "params": {"field": "rule.id", "size": 20, "order": "desc", "orderBy": "1"}},
            ],
        },
        [{"meta": {"alias": None, "disabled": False, "negate": False}, "query": {"range": {"rule.id": {"gte": "100000", "lte": "100499"}}}}],
    ),
    (
        "railsoc_vis_severity_pie",
        "Overview: alert severity distribution",
        {
            "title": "Overview: alert severity distribution",
            "type": "pie",
            "params": {"addTooltip": True, "addLegend": True, "legendPosition": "right", "isDonut": True},
            "aggs": [
                {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
                {"id": "2", "enabled": True, "type": "terms", "schema": "segment", "params": {"field": "rule.level", "size": 10, "order": "desc", "orderBy": "1"}},
            ],
        },
        [{"meta": {"alias": None, "disabled": False, "negate": False}, "query": {"range": {"rule.id": {"gte": "100000", "lte": "100499"}}}}],
    ),
    (
        "railsoc_vis_detection_timeline",
        "Overview: detection timeline (all RailSOC rules)",
        {
            "title": "Overview: detection timeline (all RailSOC rules)",
            "type": "histogram",
            "params": {"grid": {}, "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom", "scale": {"type": "linear"}, "labels": {"show": True}, "title": {}}], "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left", "scale": {"type": "linear", "mode": "normal"}, "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100}, "title": {"text": "Count"}}], "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked", "data": {"label": "Count", "id": "1"}, "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True, "showCircles": True}], "addTooltip": True, "addLegend": True, "legendPosition": "right", "times": [], "addTimeMarker": False},
            "aggs": [
                {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
                {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment", "params": {"field": "timestamp", "interval": "auto", "min_doc_count": 1}},
                {"id": "3", "enabled": True, "type": "range", "schema": "group", "params": {"field": "rule.id", "ranges": [{"from": 100100, "to": 100199, "label": "A: admin access"}, {"from": 100200, "to": 100299, "label": "B: Modbus"}, {"from": 100300, "to": 100399, "label": "C: PIS disruption"}, {"from": 100400, "to": 100499, "label": "ML"}]}},
            ],
        },
        [{"meta": {"alias": None, "disabled": False, "negate": False}, "query": {"range": {"rule.id": {"gte": "100000", "lte": "100499"}}}}],
    ),
]


def build():
    for vis_id, title, state, filters in VISUALIZATIONS:
        res = make_vis(vis_id, title, state, filters)
        print("vis:", vis_id, "->", "ok" if "id" in res else res)

    panels = []
    layout = [
        (0, 0, 24, 15), (24, 0, 24, 15),  # panel 1
        (0, 15, 24, 15), (24, 15, 24, 15),  # panel 2
        (0, 30, 24, 15), (24, 30, 24, 15),  # panel 3
        (0, 45, 48, 15),  # panel 4
        (0, 60, 16, 15), (16, 60, 16, 15), (32, 60, 16, 15),  # panel 5
    ]
    vis_ids = [v[0] for v in VISUALIZATIONS]
    references = []
    for i, (vis_id, (x, y, w, h)) in enumerate(zip(vis_ids, layout, strict=True), start=1):
        ref_name = f"panel_{i}"
        panels.append(
            {
                "version": "2.13.0",
                "type": "visualization",
                "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i)},
                "panelIndex": str(i),
                "embeddableConfig": {},
                "panelRefName": ref_name,
            }
        )
        references.append({"name": ref_name, "type": "visualization", "id": vis_id})

    dashboard_body = {
        "attributes": {
            "title": "RailSOC M3 - Detection Dashboard",
            "description": "Authentication (A), Modbus (B), PIS (C), ML alerts, and a security overview - built from real lab/attack evidence (see docs/report/evaluation.md).",
            "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
            "version": 1,
            "timeRestore": False,
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})},
        },
        "references": references,
    }
    res = call("POST", "/api/saved_objects/dashboard/railsoc_m3_dashboard?overwrite=true", dashboard_body)
    print("dashboard:", "ok" if "id" in res else res)


def export(out_path):
    body = {
        "type": ["index-pattern", "visualization", "dashboard"],
        "includeReferencesDeep": True,
    }
    req = urllib.request.Request(
        BASE + "/api/saved_objects/_export",
        data=json.dumps(body).encode(),
        method="POST",
    )
    req.add_header("osd-xsrf", "true")
    req.add_header("Content-Type", "application/json")
    import base64

    token = base64.b64encode(f"{AUTH[0]}:{AUTH[1]}".encode()).decode()
    req.add_header("Authorization", f"Basic {token}")
    with urllib.request.urlopen(req, context=CTX) as resp:
        content = resp.read().decode()
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)
    print("exported to", out_path, "(", content.count("\n"), "lines)")


if __name__ == "__main__":
    if "--export" in sys.argv:
        export("src/detection/siem/dashboards/railsoc_dashboard.ndjson")
    else:
        build()
