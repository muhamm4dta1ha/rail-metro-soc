# SIEM queries (task M3-07)

Starter templates for the Wazuh Dashboard (OpenSearch Dashboards, DQL) - **validate every query against real data** and replace this file with the final queries + result screenshots. JSON-decoded schema fields live under `data.*` in the Wazuh indexer; Wazuh's own fields are `rule.id`, `rule.level`, `rule.mitre.id`, `agent.name`.

| Scenario | Question | Starter query (DQL) | Then |
|---|---|---|---|
| A | Which sources fail to log in to the PIS? | `data.event.dataset:"pis.app" and data.event.action:"login" and data.event.outcome:"failure"` | Visualise count by `data.source.ip` over time |
| A | Did a failure burst end in a success? | `data.event.dataset:"pis.app" and data.event.action:"login" and data.source.ip:"<ip from above>"` | Sort by time; look for failure... success |
| B | Who writes to the controllers? | `data.event.dataset:"scada.command" and not data.source.ip:"10.60.10.23"` | Compare with the baseline window |
| B | Any source outside the asset inventory? | `data.event.dataset:"gw.firewall" and not data.source.ip:(<inventory IPs>)` | Generate the list from `src/simulation/config/assets.csv` |
| C | Are errors rising? | `data.event.dataset:"pis.app" and data.http.response.status_code >= 500` | Count per 10 s, overlay request rate |
| ML | What did the model flag? | `data.event.dataset:"ml.alert"` | Compare with rule alerts per run |
| All | Which rules fired? | `rule.id >= 100000 and rule.id < 100500` | Aggregate by `rule.id` and `rule.mitre.id` |

For each final query record: scenario, time window (from `lab/ground_truth/attack_runs.csv`), result count for the attack run vs the baseline run, and a screenshot path under `src/detection/siem/queries/screens/`.
