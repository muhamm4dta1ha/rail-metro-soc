# Event schema (contract v0.1)

**Owner: Talha** - **Consumers: Roshni** (SIEM rules and queries), **Anum** (ML features), **Furqan** (evidence and ground truth) - machine-readable form: `src/common/railsoc_common/schemas/event.schema.json`

Every module that produces or reads log/telemetry/alert events uses this contract. One event = one JSON object per line (JSON Lines, UTF-8).

## Rules (HC-19)
1. Every event validates against the schema (`railsoc_common.events.validate_event`). CI tests fail otherwise.
2. **Ground-truth labels never appear inside events** (`label`, `attack`, `scenario`, `run_id`, ... are rejected). Labels live only in `lab/ground_truth/attack_runs.csv`.
3. Timestamps are **UTC**, ISO-8601 with milliseconds and a trailing `Z`: `2026-01-05T09:00:03.120Z`.
4. `host.name` is the machine that **produced** the log line; `asset` is the asset the event is **about** (the target or subject).
5. Only the fields below exist. New fields need a contract change (see the end of this file).

## Fields

| Group | Field | Type | Notes |
|---|---|---|---|
| (root) | `@timestamp` | string | required, UTC |
| (root) | `message` | string | free text; **never used as an ML feature** |
| (root) | `tags` | string[] | optional |
| `event` | `dataset` | string | required, e.g. `pis.app` (lowercase, dot separated) |
| `event` | `category` | enum | required: authentication, network, configuration, availability, process, telemetry, web, session, intrusion_detection |
| `event` | `action` | string | required, e.g. `login`, `request`, `poll`, `write_register`, `anomaly_detected` |
| `event` | `outcome` | enum | required: success, failure, unknown |
| `event` | `duration_ms` | number | optional |
| `host` | `name` | string | required |
| `asset` | `id`, `zone`, `type` | string | zone is one of corporate_it, dmz_ops, station_field, attacker_lab, soc_mgmt |
| `source`, `destination` | `ip`, `port`, `mac` | string / int | `ip` must be IPv4 |
| `network` | `protocol`, `transport`, `bytes`, `packets` | string / int | transport: tcp, udp, icmp, other |
| `user` | `name`, `role` | string | |
| `http` | `request.method`, `response.status_code`, `response.latency_ms` | | |
| `url` | `path` | string | |
| `modbus` | `function_code`, `unit_id`, `address` | int | write function codes: 5, 6, 15, 16 |
| `mqtt` | `topic`, `client_id`, `qos` | | |
| `metric` | `name`, `value`, `unit` | string / number | `name` and `value` required |
| `ml` | `model`, `score`, `threshold`, `window_start`, `window_end`, `top_features` | | used by `ml.alert` only |

## Datasets

| `event.dataset` | Produced by | Category | Typical actions |
|---|---|---|---|
| `pis.app` | PIS service (Talha) | authentication, web, configuration | login, request, config_change, user_create |
| `auth.ssh` | jump host (Talha) | authentication, session | login, logout, sudo |
| `scada.poll` | OCC poller (Talha) | telemetry | poll |
| `scada.command` | station controllers / gateway (Talha) | configuration | write_register |
| `gw.firewall` | gateway (Talha) | network | allow, deny |
| `mqtt.broker` | MQTT broker (Talha) | network, availability | publish, connect, disconnect |
| `signaling.test` | non-operational signaling-test log generator (Talha) | process | fictional message names |
| `svc.health` | health checker (Talha) | availability | healthcheck |
| `net.flow` | network sensor (Talha, Roshni) | network | flow |
| `ml.alert` | ML detector (Anum) | intrusion_detection | anomaly_detected |

## Examples

```json
{"@timestamp":"2026-01-05T09:00:03.120Z","event":{"dataset":"pis.app","category":"authentication","action":"login","outcome":"failure"},"host":{"name":"pis-01"},"asset":{"id":"PIS-01","zone":"dmz_ops","type":"pis_server"},"source":{"ip":"10.60.66.10","port":40122},"destination":{"ip":"10.60.20.10","port":8080},"network":{"protocol":"http","transport":"tcp"},"user":{"name":"ops_admin"},"http":{"request":{"method":"POST"},"response":{"status_code":401}},"url":{"path":"/api/login"},"message":"login failed for ops_admin"}
```

```json
{"@timestamp":"2026-01-05T09:00:10.000Z","event":{"dataset":"ml.alert","category":"intrusion_detection","action":"anomaly_detected","outcome":"unknown"},"host":{"name":"ml-detector"},"source":{"ip":"10.60.66.10"},"ml":{"model":"ocsvm","score":0.81,"threshold":0.62,"window_start":"2026-01-05T09:00:00.000Z","window_end":"2026-01-05T09:00:10.000Z","top_features":["n_failures","n_http_4xx","n_events"]},"message":"anomalous activity from 10.60.66.10 in a 10s window"}
```

## In code

```python
from railsoc_common.events import make_event, write_events

event = make_event("pis.app", "authentication", "login", "failure",
                   host={"name": "pis-01"}, source={"ip": "10.60.66.10"}, user={"name": "ops_admin"})
write_events("lab/data/raw/sample.jsonl", [event])
```

## Changing the contract
Open a PR that changes the schema, this document **and** the tests; Talha (owner) and at least one consumer approve; announce it in the team chat; bump `CONTRACT_VERSION` in `src/common/railsoc_common/__init__.py` when fields change.
