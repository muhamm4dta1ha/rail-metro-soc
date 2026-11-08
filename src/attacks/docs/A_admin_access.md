# Scenario A — Unauthorized Administrative Access

## Objective and scope
Demonstrate repeated failed authentication followed by a valid login from the same lab source.
Only PIS `10.60.20.10:8080/api/login` is implemented. No SSH guessing or configuration change.

## Procedure
Run `src/attacks/scripts/run_lab.ps1 -RoeApproved -Campaign -Scenarios A` after all four RoE
approvals and with the existing services running. This verifies isolated DMZ membership, uses
`10.60.20.99` for the test, and compares with OCC `10.60.20.20`.
The individual test sends five requests for an invalid synthetic account then one login for
the existing synthetic PIS account. Credentials are read from environment, never parameters.
The campaign varies rate 2–6/s and duration 4–5s; an individual run lasts 6s. Every comparison
has the same configured duration, but only one normal successful login.

## Expected and observed indicators
The completed campaign produced 11 attack runs: 55 HTTP 401 responses and 11 HTTP 200 responses.
Each of 11 baselines had one successful scripted login. The packet export independently shows
those attack response codes. Success means the preconfigured synthetic account worked; it does
not demonstrate password discovery, privilege escalation or administrative modification.

## Evidence and packet analysis
See `lab/evidence/runs/M2-20261108T050042Z/`: `A-attack.pcap`, `A-baseline.pcap`,
`A-packet-observations.tsv`, execution transcripts and per-run `events.jsonl`/`manifest.json`.
Use `http.response.code == 401 && ip.dst == 10.60.20.99` or
`http.response.code == 200 && ip.dst == 10.60.20.99`. Use frame time bounds from the manifest.
Server-response-only captures exclude credential-bearing requests. Use actual PIS server logs
for usernames and endpoint correlation; client logs are clearly named `pis.client`.

## Detection and mitigation
Correlate repeated login failures followed by success from a new source. Restrict administrative
sources, rate-limit authentication and use stronger authentication. Do not treat ordinary single
login mistakes as attacks. Roshni must validate the Wazuh rules against the real server logs.
