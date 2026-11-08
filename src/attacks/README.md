# Module 2 — Attack Generation

Owner: Furqan. Reviewer: Talha. Exactly three scenarios; approved synthetic lab only.

The runners now execute bounded HTTP and read-only Modbus traffic through the existing
`ScenarioBase`, `RunContext`, `LabScope`, recorder and campaign interfaces. No simulation,
shared-schema or network-isolation changes are required.

| Scenario | Real operation | Comparison |
|---|---|---|
| A | Five invalid synthetic PIS logins, then one configured valid login | One valid OCC login |
| B | Function 3 reads of monitoring registers 0–3; no writes | Same reads from OCC at <=1/s |
| C | Sequential GET /api/arrivals, with baseline, test and recovery phases | <=1/s throughout |

## Offline checks

```powershell
.venv\Scripts\python.exe -m pytest -q src/attacks/tests/
.venv\Scripts\python.exe -m railsoc_attacks.cli list
.venv\Scripts\python.exe -m railsoc_attacks.cli run A
.venv\Scripts\python.exe -m railsoc_attacks.cli run B --campaign
```

Dry runs produce manifests only, under `lab/evidence/runs/dry_runs`. They are not attack
evidence, synthetic training events or ground-truth records. Tests mock network clients.

## Reproduce the live evidence

All four members must first approve [RoE](RULES_OF_ENGAGEMENT.md). Start Docker Desktop
and the existing simulation services (including OCC); do not recreate FUXA or its volumes.
The PIS must already have a synthetic account configured in its environment. The script
reads it into process memory and passes it to the temporary clients without printing it.

```powershell
docker compose -f src/simulation/docker-compose.yml start pis station-plc mqtt-broker jumphost fuxa occ
& src/attacks/scripts/run_lab.ps1 -RoeApproved -Campaign
```

The script uses cached `rail-metro-soc-occ` and `nicolaka/netshoot:latest` images. Build
M1's images using its existing instructions if absent. Versions/image hashes are part of
the evidence; floating upstream image tags are a reproducibility limitation.

The original gateway does not route between zones. This M2 alternative creates one temporary
client on **only** the existing internal DMZ at **10.60.20.99**. It never attaches the existing
attacker to another network, changes isolation, spoofs an address, or enables routing.
Normal comparisons share the existing OCC network namespace (**10.60.20.20**). Both bind
their actual source address. Targets are PIS **10.60.20.10:8080** and PLC **10.60.20.22:502**.
The station-field source **10.60.30.99** remains the original B default for a future routed
lab; use the script for the current topology. The DMZ substitute is documented, not claimed
to be a station-zone intrusion.

Every scenario gets one individual run and ten deterministic campaign variants, with matching
baseline variants. The script checks isolation/targets before each scenario, tests the kill
switch, captures traffic, stops on unsuccessful individual observations, and removes only its
own temporary containers. Normal OCC background traffic remains enabled.

Create `.kill_attacks` in the repository to stop clients; remove it yourself before restarting.
Requests are sequential, with no redirects, proxies, automatic retries or service modifications.
A/B request counts are bounded; C uses one total deadline including recovery. Blocking network
operations use <=1 second timeouts limited by remaining duration. OS scheduling can slightly
overshoot deadlines. No service restart or persistent restoration is needed.

For manual CLI execution **inside a verified namespace**:

```powershell
python -m railsoc_attacks.cli run A --live --roe-approved --isolation-verified --param attacker_ip=10.60.20.99
python -m railsoc_attacks.cli run B --live --roe-approved --isolation-verified --param attacker_ip=10.60.20.99
python -m railsoc_attacks.cli run C --live --roe-approved --isolation-verified --param attacker_ip=10.60.20.99
```

A requires process environment `M2_PIS_USER` and `M2_PIS_PASSWORD`. Do not put secrets in
`--param`. `--baseline` selects OCC. `--campaign` uses the existing Cartesian sweep framework;
`lab_batch.py` is its short live-lab profile, not another campaign system. The lower-level
Python recorder API assumes its caller has performed RoE and isolation checks.

## Evidence and handoff

Each live run writes `manifest.json`, `events.jsonl`, `SHA256SUMS` and a ground-truth CSV row.
Status `completed` means execution finished; consult measurements to establish observed success.
Client observations use `pis.client`/`scada.poll`; PIS server events remain `pis.app`.
Labels never enter events. The shared schema has no `event.id`; the evidence audit supplies
stable file/line identifiers externally. Do not add a label or run ID to model features.

```powershell
python -m railsoc_attacks.audit_evidence lab/evidence/runs/M2-<session-UTC>
```

HTTP captures are server-to-client only, deliberately excluding login request bodies/passwords.
They prove response codes and timing, not complete TCP conversations or HTTP request contents.
Modbus captures include both directions. Baseline captures include OCC background traffic;
use run windows and the client event files for the exact scripted observations.

See [the report](docs/M2_Attack_Simulation_Report.md), [A](docs/A_admin_access.md),
[B](docs/B_rogue_device.md), and [C](docs/C_service_disruption.md).
Share the session evidence directory, `lab/ground_truth/attack_runs.csv` and optional merged
JSONL privately with teammates. Do not stage raw events, PCAPs, local environment files or
archives. The repository does not ignore all live evidence; stage explicit source paths only.
