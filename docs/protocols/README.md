# Protocol-stack discussion (deliverable 2)

**Owner: Talha** (tasks M1-02, M1-05, M1-11) - **Reviewer: Roshni** (uses it for Wireshark) and **Anum** (uses it for features).

Files to write: `protocol_stack.md`, `register_map.md`, `signaling_test_log_format.md`, `log_to_packet_correlation.md`.

Starter table (verify against the lab and expand to layers 1-7 per flow):

| Flow | Transport / port | Security properties | Normal behaviour (to measure) | What an anomaly looks like |
|---|---|---|---|---|
| Staff -> PIS portal/API (HTTP) | TCP 8080 in the lab (80/443 in production) | HTTP is clear text; login by password | few logins per hour, rare typos, steady arrivals polling | burst of 401 from one source; success after failures |
| Displays <- MQTT broker | TCP 1883 (8883 with TLS) | lab broker allows anonymous clients | regular publishes from the PIS | publishes from an unknown client id or source |
| OCC poller -> station controllers (Modbus/TCP) | TCP 502 | no authentication or encryption by design | fixed-interval reads (function code 3) | write function codes (5, 6, 15, 16) from a non-authorised source; new source |
| Engineer -> jump host (SSH) | TCP 22 | encrypted, key or password | maintenance window only | failures from a new source, logins out of hours |
| Assets -> SIEM (syslog / agent) | agent and syslog ports per Wazuh docs | verify TLS options | steady log volume | gaps in the stream (a silenced source) |
| NTP, DNS | UDP 123, UDP/TCP 53 | NTP is unauthenticated by default | periodic | unexpected servers or query bursts |

Railway context to cover (described, **not simulated**): GSM-R/FRMCS and CBTC radio links, safety signaling protocols; use the EN 50159 threat categories (corruption, repetition, deletion, insertion, resequencing, delay, masquerade) as the vocabulary for "what could go wrong" and map each to a detection signal.
