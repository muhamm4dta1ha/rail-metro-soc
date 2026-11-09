
# Feature catalogue

Each row describes one source IPv4 address in one fixed UTC window. Events without a source IP share a missing-source group for that window. Counts, rates and statistics describe observed events. Missing values and undefined feature ratios are encoded as zero. For HTTP latency and telemetry, sample counts provide context for the zero fill.

| Feature | Meaning | Event fields |
|---|---|---|
| `n_events` | Number of events | Count of rows |
| `n_failures`, `failure_ratio` | All failed events and their share of all events | `event.outcome` |
| `n_unique_dst_ip`, `n_unique_dst_port` | Distinct reported destinations and nonzero destination ports | `destination.ip`, `destination.port` |
| `n_http_4xx`, `n_http_5xx` | Client and server error counts | `http.response.status_code` |
| `n_modbus_write` | Number of Modbus writes with codes 5, 6, 15 or 16 | `modbus.function_code` |
| `n_mqtt_publish` | MQTT publish count | `network.protocol`, `event.action` |
| `n_new_source` | Known source address absent from the optional pre-existing inventory. Zero when the inventory is disabled or the event has no IP | `source.ip`, asset inventory `ip` |
| `n_auth_failures`, `auth_failure_ratio` | Failed authentication events and their share of authentication events | `event.category`, `event.outcome` |
| `http_requests_per_s` | HTTP event count divided by full window length. A request method, response status, or HTTP protocol with action `request` counts once | `http.request.method`, `http.response.status_code`, `network.protocol`, `event.action` |
| `mean_http_latency_ms`, `n_http_latency_samples` | Average over reported latency values and number of values | `http.response.latency_ms` |
| `n_modbus_read` | Number of Modbus reads with codes 1–4 | `modbus.function_code` |
| `modbus_fc_{1,2,3,4,5,6,15,16}_ratio`, `modbus_fc_other_ratio` | Eight code shares plus the share for all other observed codes. Denominator is the number of events reporting a function code | `modbus.function_code` |
| `n_mqtt_connect`, `n_mqtt_topics` | MQTT connect count and number of distinct nonempty topic strings | `network.protocol`, `event.action`, `mqtt.topic` |
| `network_bytes`, `network_packets` | Sum of reported bytes and packets | `network.bytes`, `network.packets` |
| `n_metric_samples` | Number of telemetry values present | `metric.value` |
| `station_temp_c_mean`, `station_temp_c_range` | Mean and max minus min for station temperature in C | `metric.name`, `metric.value`, `metric.unit` |
| `feeder_voltage_v_mean`, `feeder_voltage_v_range` | Mean and range for feeder voltage in V | Same metric fields |
| `platform_occupancy_pct_mean`, `platform_occupancy_pct_range` | Mean and range for platform occupancy in percent | Same metric fields |
| `lift_available_mean`, `lift_available_range` | Mean and range for lift availability, encoded as numeric booleans | Same metric fields |

The first ten features are the starter set. Models select columns explicitly by name. Source IP is a grouping key and stays outside the feature matrix. Raw endpoint identities, user or asset identities, timestamps, messages, labels, run IDs, scenarios and ground-truth participant metadata stay outside it too. The inventory flag uses the full fixed inventory, including its listed attacker host. Omit `--assets` to disable it. Topic names and destination addresses contribute only to cardinality. Telemetry values are grouped by known metric and expected unit so incompatible readings are never averaged together.
