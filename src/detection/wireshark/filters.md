# Wireshark analysis (tasks M3-05 / M3-06)

Starter filters and views. Replace with the final, tested set and keep the importable Wireshark profile in `profile/`. Capture source: rotating pcaps from the gateway (task M1-09). Always compare an attack window with its baseline window (`lab/ground_truth/attack_runs.csv`).

| Goal | Where / filter |
|---|---|
| Protocol mix per zone (feeds the protocol-stack discussion) | Statistics > Protocol Hierarchy |
| Who talks to whom | Statistics > Conversations / Endpoints (sort by packets, look for new endpoints) |
| Rate spikes and drops | Statistics > I/O Graphs (per-source filters, e.g. `ip.src == 10.60.66.10`) |
| Login failures (A) | `http.response.code == 401` ; `http.request.method == "POST" && http.request.uri contains "login"` |
| SSH session volume (A) | `tcp.port == 22` and Conversations: many short flows from one source |
| Discovery pattern (B) | `tcp.flags.syn == 1 && tcp.flags.ack == 0` then Conversations: one source, many ports/hosts |
| Modbus requests (B) | `modbus` ; write functions: `modbus.func_code in {5 6 15 16}` |
| MQTT publishes (B) | `mqtt` ; `mqtt.msgtype == 3` (PUBLISH), add `mqtt.topic` and `mqtt.clientid` columns |
| Service stress (C) | `tcp.analysis.retransmission \|\| tcp.analysis.zero_window` ; `http.response.code >= 500` ; Expert Information |
| One session end to end | Right click > Follow > TCP Stream |

For every indicator document: filter used, what it shows in the attack vs the baseline, the screenshot path, and the matching SIEM event (task M1-11 maps log lines to packets).
