# M3 Alerting and Triage Playbooks (task M3-09)

One page per scenario: detect, triage, contain, recover. Severities and rule IDs match
`src/detection/siem/rules/railsoc_rules.xml`; real counts and behaviour are in
[evaluation.md](evaluation.md) - this page is the "what do you actually do" companion to that
writeup, written for whoever is on the SOC desk during the demo or a real exercise.

No active-response (automatic containment) is configured anywhere in this lab - every contain
step below is a manual action a human takes, deliberately, given HC-02/HC-18 (nothing here should
ever be able to reach back out and touch a real network on its own).

---

## Scenario A - Unauthorized administrative access (PIS login)

| Severity | Rule(s) | Meaning |
|---|---|---|
| Low (level 3) | 100100 | One failed PIS login. Expected background noise - `http_driver.py`'s own typo-login rate means a handful of these per hour from `10.60.20.20` (OCC) are normal. |
| Low (level 3) | 100103 | One successful PIS login (audit only - not itself suspicious). |
| **High (level 10)** | 100101 | 5+ failed logins from **one source** within 60 s. Not background noise - this is the alert that pages someone. |

**Detect.** A 100101 alert fires, or the dashboard's Auth panel shows a spike for one source IP.

**Triage (in order, ~2 minutes):**
1. Pull the source IP from the alert (`data.source.ip`). Check it against
   `src/simulation/config/assets.csv` - PIS/OCC/jump-host staff addresses are all listed; anything
   else is not a known lab asset.
2. Run the scenario A second query from `siem/queries/queries.md` ("Did a failure burst end in a
   success?") for that source and the next ~60 s. A success afterward escalates this - it means
   the credential-guessing worked.
3. Check `data.user.name` across the failed attempts: a tight rotation through 1-2 account names
   (as opposed to one name mistyped) points at credential stuffing rather than one user fumbling
   their own password.

**Contain:**
- If the source is not a known asset and a success followed: treat as confirmed compromise of
  whatever PIS account logged in. In the real lab, that means: note the account, and (if this were
  a live exercise rather than a one-off demo) have Talha's side block the source at the gateway and
  force a password reset on the account via the PIS admin portal.
- If the source *is* a known asset (e.g. `10.60.20.20`) with no success following: almost
  certainly the benign typo-login look-alike - log and move on, no containment needed.

**Recover:** rotate the credential that succeeded; confirm no further 100101/100103 pair from the
same source after containment; note the run/alert IDs in the incident record.

---

## Scenario B - Unauthorized Modbus reads from a rogue device

| Severity | Rule(s) | Meaning |
|---|---|---|
| **High (level 10)** | 100200 | A Modbus **write** (function 5/6/15/16) from outside the allow-list (`10.60.10.23`, `10.60.20.20`). Writes change controller state - treat with urgency even on a monitoring-class device (HC-22). |
| Medium (level 8) | 100201 | A single unauthorized **read** (function 3) - could be a one-off scan. |
| **High (level 10)** | 100202 | Repeated unauthorized reads, same source within 30 s - an active rogue poller, not a one-off. |

**Detect.** Any 100200/100201/100202 alert; the dashboard's Modbus panel shows a non-approved
source.

**Triage (~2 minutes):**
1. Confirm the source IP is genuinely not `10.60.20.20` (OCC, the only approved poller) or
   `10.60.10.23` (the engineering workstation address, for writes) - `queries.md`'s Modbus query
   does this directly.
2. For a write (100200): check `data.modbus.address` - this lab's only legitimate write target is
   the setpoint register (`SETPOINT_REGISTER` in `railsoc_sim/protocol_map.py`); any other address
   written is more unusual still.
3. For reads (100201/100202): note the register addresses read (0-3 in this scenario) - reading
   the same small range repeatedly is reconnaissance, not a real poller probing broadly.

**Contain:**
- A write from an unknown source is the most serious case here: the containment action is a
  network-layer block (ACL/firewall on the `dmz_ops` segment) - detection (this rule) is not a
  substitute for that, and the mitigation table in evaluation.md says so explicitly. Modbus/TCP has
  no authentication of its own.
- A repeated-read source gets the same network-layer block; a single read gets logged and watched
  for escalation to 100202.

**Recover:** confirm no further unauthorized Modbus traffic from the blocked source; if a write
actually landed, verify the controller's setpoint against its expected value and correct it if
needed (station telemetry is monitoring-class, not safety-related, but still worth confirming).

---

## Scenario C - PIS service disruption (abnormal request rate)

| Severity | Rule(s) | Meaning |
|---|---|---|
| Low (level 3) | 100300, 100302 | A single PIS 5xx, or the base rate-tracking rule. Neither is itself an alarm - 100302 fires on every PIS request by design. |
| **High (level 10)** | 100301 | A burst of PIS 5xx. In practice this PIS stub doesn't return 5xx under load (see evaluation.md) - kept for a real deployment where the backend might actually degrade. |
| **High (level 10)** | 100303 | Sustained request rate (>=2 req/s) from one source. **This is the rule that actually catches scenario C** in this lab. |

**Detect.** A 100303 alert, or a visible spike in the dashboard's PIS rate-timeline panel for one
source against a flat baseline.

**Triage (~1 minute - this one is time-sensitive, it's a disruption in progress):**
1. Confirm it's one source, not many (`data.source.ip` on the alert) - a real distributed flood
   would need a different response than one noisy client.
2. Check whether PIS is actually degrading: `queries.md`'s "are errors rising" query
   (`data.http.response.status_code >= 500`). If it's 0 while the rate alert is firing, this is a
   rate anomaly *without* an actual outage yet - exactly the honest distinction evaluation.md draws
   out. Don't over-claim an outage that isn't happening.
3. Watch the request rate after the alert: does it recover on its own (bounded test, as this
   scenario's own code does) or keep climbing?

**Contain:**
- Rate-limit or temporarily block the source IP at the gateway/reverse-proxy layer. The PIS stub
  itself (`pis_stub.py`, a plain `ThreadingHTTPServer`) has no rate limiting of its own - that is a
  real gap worth fixing ahead of detection, per the mitigation table in evaluation.md.
- If genuine 5xx/timeouts start appearing (100300/100301 joining 100303), escalate: this has moved
  from "anomalous rate" to "actual degradation."

**Recover:** confirm the request rate from that source has dropped back under ~1 req/s; confirm
100303 stops firing; if an actual outage occurred, record start/end time from the 100300/100301
alerts for the incident timeline.

---

## ML alerts (100400)

Treat an `ml.alert` (rule 100400) as a *lead*, not a verdict - the evaluation (section 6,
evaluation.md) shows real precision/recall numbers (0.86 / 0.60 on this dataset), so false
negatives are expected and a false positive is possible. Triage: pull `data.ml.top_features` from
the alert (what made the model flag this window) and check whether the same window also has a
rule-based alert for one of A/B/C - if it does, the ML alert corroborates it; if it doesn't, treat
it as worth a look rather than an automatic escalation.
