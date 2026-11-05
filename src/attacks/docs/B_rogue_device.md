# Scenario B - Anomalous communications from a rogue device

Status: **starter** (objective + expected indicators). Procedure and runner: task M2-05 - Owner: Furqan - Reviewer: Talha (Roshni checks the indicators)

## Objective
Show how an unknown device appearing in the station network and talking in ways the baseline never shows looks to a SOC. Brief category: *anomalous communications*.

## Scope & safety
- The rogue device is a lab container in the station zone with an address that is **not** in `src/simulation/config/assets.csv` (that is the point). Targets: simulated station *monitoring* controllers and the MQTT display broker only.
- **No safety-related function** is simulated or touched: no points, signals, interlocking or train protection (RoE rule 5). Caps and kill switch as in the RoE.

## ATT&CK mapping (verify ids on attack.mitre.org)
T1046 Network Service Discovery; ICS: T0846 Remote System Discovery, T0855 Unauthorized Command Message, T0856 Spoof Reporting Message.

## Preconditions
Lab up with normal telemetry and display traffic (M1-05), gateway capture running (M1-09), asset inventory loaded into the SIEM as the "known assets" list (M3-02).

## Procedure (reproducible)
TO WRITE (M2-05): how the rogue container is attached to the station zone, tools + pinned versions, parameters, start/stop, clean-up.

## Expected indicators (by layer)
| Layer | What should be visible |
|---|---|
| Network (Wireshark) | A new source address/MAC in the station zone; many SYNs to many ports/hosts in seconds; Modbus requests with *write* function codes from a non-master; MQTT PUBLISH from an unknown client id |
| Host / app logs | Gateway `gw.firewall` entries for the new source; controller `scada.command` events from a source other than the engineering workstation; broker publish events from an unknown client |
| SIEM | New-asset alert (source not in inventory), discovery-pattern correlation, unauthorised-writer rule |
| ML features | `n_new_source`, `n_unique_dst_ip`, `n_unique_dst_port`, `n_modbus_write`, `n_mqtt_publish` for the rogue source |

## Expected events (contract datasets)
`gw.firewall`, `scada.command` (configuration/write_register), `mqtt.broker` (publish/connect), `net.flow`.

## Evidence collected (per run - automated by the recorder)
`manifest.json`, pcap slice, controller/broker/gateway log slices, SIEM alert export, screenshots.

## Baseline for comparison (M2-07)
Same window without the rogue device. It contains the *authorised* maintenance writes from the engineering workstation (benign look-alike) so that "any write = attack" is not learnable.

## Mitigation recommendations (input to M2-12 and the report)
- Prevent: port security / 802.1X on station switches, protocol allow-listing at the gateway, authenticated + TLS MQTT, segmentation between displays and controllers.
- Detect: asset-inventory diffing, discovery-pattern rule, function-code allow-list per source.
- Respond: isolate the port/host, review controller state, rotate broker credentials.

## Status checklist
- [ ] procedure written
- [ ] runner implemented (guarded by `ctx.guard`)
- [ ] indicators confirmed in pcap and logs
- [ ] baseline captured
- [ ] Module 3 detects it
- [ ] Module 4 features cover it
- [ ] reviewed by the ring reviewer
