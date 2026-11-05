# Dashboards (task M3-08)

Export the final dashboard as Dashboards saved objects (`*.ndjson`) into this folder and commit it, together with the import steps, so anyone can restore it into a fresh SIEM.

Planned panels (replace with the real list):

1. **Overview** - alerts over time by severity; alerts by scenario group (`railsoc_a`, `railsoc_b`, `railsoc_c`, `railsoc_ml`).
2. **Administrative access (A)** - login failures by source, success-after-failure table, admin actions outside the maintenance window.
3. **Network anomalies (B)** - new sources not in the asset inventory, Modbus write sources, MQTT publishers.
4. **Service health (C)** - request rate, 5xx rate, latency, health-check status.
5. **Scenario timeline** - ground-truth run windows overlaid on alert counts (shows time-to-detect).
6. **MITRE ATT&CK** - techniques seen (`rule.mitre.id`).
7. **ML panel (with Module 4)** - anomaly score over time, ML vs rule alerts per run.
