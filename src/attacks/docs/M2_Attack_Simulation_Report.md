# Module 2 — Attack Generation and Evidence Report

Furqan | Rail-Metro SOC | 8 November 2026

## 1. Introduction

Module 2 generates controlled lab traffic so the Detection and ML teams can compare suspicious behavior with normal activity. I ran one demonstration and ten deterministic campaign variants for each of three scenarios, with a normal comparison for each. All traffic used the existing synthetic Docker lab.

## 2. Laboratory setup

The existing internal DMZ (10.60.20.0/24) contains the PIS at 10.60.20.10:8080, MQTT at 10.60.20.11:1883, OCC at 10.60.20.20, the monitoring PLC at 10.60.20.22:502, FUXA at 10.60.20.23:1881 and the SSH jump host at 10.60.20.30. MQTT and SSH were not attack targets. FUXA polls the PLC. The gateway does not yet route between zones.

The temporary test client used only the internal DMZ at 10.60.20.99. Baseline clients shared the existing OCC namespace and bound 10.60.20.20. The script checked container membership and network isolation and tested the kill switch before each scenario. It removed its own temporary containers afterward. Lab images and versions are recorded in the evidence; the client used Python 3.12.16 and pymodbus 3.16.2.

![Docker services during live execution](../../../lab/evidence/runs/M2-20261108T050042Z/screenshots/docker-containers.png)

## 3. Scenario A — Unauthorized administrative access

I sent five invalid synthetic logins to POST /api/login, followed by one successful login using the existing synthetic account. The normal comparison sent one valid OCC login. The aim was to detect repeated failures followed by success from one new source. The valid login demonstrates a known synthetic credential, without claiming password discovery or an administrative change.

Across 11 attack runs, the server returned 55 HTTP 401 and 11 HTTP 200 responses. The packet export confirms those counts. All 11 baseline logins succeeded. The first attack was RUN-A-20261108T050147Z-01. The live script command is shown below; see A-attack-single.txt for the actual output and the manifest for individual times and latencies.

Use http.response.code == 401 && ip.dst == 10.60.20.99 in Wireshark, then compare 200 responses for the same source and run window. The capture retains only server traffic to exclude the credential-bearing request bodies. The PIS server logs provide the endpoint and authentication context.

## 4. Scenario B — Rogue device communication

I read monitoring registers 0–3 using Modbus function 3 at 10.60.20.22:502. The unknown device used 10.60.20.99. The approved OCC client read the same points at one request per second for comparison. The original station-field source could not reach the PLC because the gateway is unfinished. This run demonstrates an unknown device inside the DMZ, without changing routes or writing registers.

The 11 attack runs completed 66 successful reads. The 11 baselines completed 51 scripted reads. The first attack was RUN-B-20261108T050344Z-01. The packet export shows 66 function-3 requests and 66 replies on the attack capture. Use modbus.func_code == 3 && ip.src == 10.60.20.99 and compare the source to the inventory. Normal OCC background traffic is also visible in the baseline capture.

## 5. Scenario C — Controlled service disruption

I increased the rate of sequential GET /api/arrivals calls to the PIS for a few seconds. The client took low-rate observations before and after the test. A separate comparison at OCC kept the lower rate throughout. The client stops sending higher-rate traffic when the test phase ends; it makes no service configuration changes.

| Phase in RUN-C-20261108T050859Z-01 | Requests | Observed requests/s | Mean latency | Success |
|---|---:|---:|---:|---:|
| Baseline | 2 | 1.33 | 15.12 ms | 2/2 |
| Test | 20 | 6.67 | 3.58 ms | 20/20 |
| Recovery | 2 | 1.33 | 2.76 ms | 2/2 |

Over the 11 successful attack runs, the observed test phase ranged from about 2.80 to 12.00 requests/s. All 205 requests across the three phases succeeded; none timed out. The observed result was a rate anomaly with no availability degradation. Short windows and connection warmup affect mean latency; the single-run baseline is too small to infer a lasting latency change.

Use http.response && ip.dst == 10.60.20.99 in an I/O graph. Compare response counts by time and use manifest phase measurements for exact scripted request counts. The C attack capture contains 205 HTTP responses.

## 6. Evidence and ground truth

Session folders below are under lab/evidence/runs. Each run has events.jsonl, manifest.json and SHA256SUMS. The ground truth for all three is lab/ground_truth/attack_runs.csv.

| Scenario | Successful attack + baseline | Session folder suffix | PCAP | Result |
|---|---|---|---|---|
| A | 11 + 11 | 050042Z | A-attack.pcap / A-baseline.pcap | 55 failures then 11 successes across runs |
| B | 11 + 11 | 050042Z | B-attack.pcap / B-baseline.pcap | 66 successful attack reads |
| C | 11 + 11 | 050851Z / 050633Z | C-attack.pcap / C-baseline.pcap | Rate spike; no outage |

Full directory names start with M2-20261108T. The final session's run-index.json maps all 68 recorded attempts to evidence and marks the two earlier C attempts excluded from the 66 successful runs. SHA-256 checks and schema/label joins passed. Audits covered 455 client events; 450 belong to successful runs. The event schema does not define event.id, so the external event index supplies file and line identifiers. No ground-truth keys were added to events.

## 7. Reproduction and screenshots

After all four RoE approvals and with the Compose services running, use:

```powershell
& src/attacks/scripts/run_lab.ps1 -RoeApproved -Campaign
```

To collect terminal screenshots manually, display each actual transcript with Get-Content: A-attack-single.txt and B-attack-single.txt from 050042Z, C-attack-single.txt and m2-tests.txt from 050851Z. Use Get-ChildItem on the session folder for the evidence listing and Import-Csv lab/ground_truth/attack_runs.csv | Select-Object -Last 12 for the ground-truth view. The Docker image above is a genuine desktop screenshot. The FUXA screenshot shows the [blank runtime](../../../lab/evidence/runs/M2-20261108T050042Z/screenshots/fuxa-blank.png) after the existing localhost relay was started.

## 8. Detection and mitigation

For A, correlate failures followed by success from a new source; restrict administrative access and rate-limit logins. For B, look for Modbus access from devices outside the approved inventory, even when they only read. For C, alert on sustained request-rate increases and correlate them with errors and latency before declaring an outage.

Roshni can use the PCAPs and lab/data/raw/m2_pis_server.jsonl for SIEM checks. Use server events for HTTP detection or client events for latency analysis; ingesting both as distinct requests would double count. Anum can use lab/data/raw/m2_client_events.jsonl with the separate ground truth, group splits by run, and exclude the two attempts marked in the index. Keep source IP out of features when testing generalization across devices; all attacks here used the same source.

## 9. Problems and limitations

The existing Windows port publication did not reach FUXA directly. The existing relay restored HTTP access, but the runtime still rendered blank. Real PLC replies independently verified the station simulation. The first C baseline missed its recovery slot; the next attempt at C attack exposed a clock-read race. Both attempts are preserved. The fixes were tested and the relevant runs repeated.

All 74 M2 tests passed. The final full check had 187 passed and one unrelated failure: test_repo_root_stays_tidy rejects the pre-existing rail-metro-soc-source.zip. Lint and Compose validation passed. The capture files are grouped by session; use UTC run windows to isolate an individual run.

## 10. Conclusion

The lab produced 33 successful controlled attack runs and 33 matching comparisons. The evidence is ready for Detection and ML review. C demonstrates a rate change without measured service degradation. No Git write operation was performed.
