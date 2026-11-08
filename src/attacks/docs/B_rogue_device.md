# Scenario B — Rogue Device Communication

## Objective and scope
Demonstrate unexpected Modbus communication from a source absent from the inventory. The real
PLC is `PLC-01`, `10.60.20.22:502`; MQTT exists at `10.60.20.11:1883` but is not used by this runner.
Only function 3 reads of original monitoring registers 0–3 are issued. No output, setpoint,
track-occupancy register, write function or safety-control function is targeted.

## Placement and procedure
The original `10.60.30.99` station-zone source cannot reach the DMZ because routing is unfinished.
The laboratory-compatible alternative is a single-interface DMZ client at `10.60.20.99`,
created on the existing internal network. Existing networks and attacker attachments remain
unchanged. This is a DMZ rogue-device demonstration, not a station-zone compromise.

Run `src/attacks/scripts/run_lab.ps1 -RoeApproved -Campaign -Scenarios B`. The script verifies
isolation and target membership. Clients bind their real IP. The normal client shares OCC's
namespace at `10.60.20.20`, reads the same points at <=1/s and uses the same duration.
Attack variants request 2–6 reads/s for 4–5 seconds, six requests maximum; the individual test
lasts 6s. Calls are sequential, time-limited, guarded and never automatically retried.

## Results and evidence
All 11 attack runs completed with six successful reads each (66 total). Eleven baselines
produced 51 scripted reads. `lab/evidence/runs/M2-20261108T050042Z/` contains both PCAPs,
`B-packet-observations.tsv`, transcripts and per-run manifests/logs. The baseline capture also
contains M1 normal traffic, including its authorised maintenance writes; those are not M2 writes.

Wireshark: `modbus && ip.addr == 10.60.20.99`; requests:
`modbus.func_code == 3 && ip.src == 10.60.20.99`. The attack capture should contain no functions
5, 6, 15 or 16. Compare source addresses and request spacing with the baseline capture. No
source IP spoofing or external routing was used.

## Detection and mitigation
Detect an unapproved client accessing the monitoring service, even when requests are reads.
Use source allow-lists and zone firewall rules; investigate new devices. Frequency alone is
not sufficient because legitimate OCC polls can be bursty. Update inventory-based detection
for the actual DMZ placement rather than assuming the original station-zone address.
