
# Module 4 report | Anum Ali

## What the detector does

The detector looks for unusual activity in the railway SOC lab. The three scenarios are unauthorized administrative access, rogue-device communication and service disruption. A score above the model's threshold raises an alert for a source and a 10-second time window. The alert is a starting point for investigating the event logs.

## What went into training

The checkout had an asset inventory with 24 entries and a ground-truth CSV with zero runs. We generated 66,985 normal events using Talha's offline simulator. The pipeline validated the events and formed 8,884 source windows. In a campaign, Furqan's CSV would also mark direct attack activity, victim impact and explicit baseline runs.

The 38 numeric features describe traffic volume, login failures, HTTP errors and latency, destination diversity, Modbus activity, MQTT activity, flow measurements and telemetry. Labels and campaign metadata stay outside the model. The workflow trains on earlier windows, sets anomaly thresholds on a separate normal slice and tests on later windows. It keeps each campaign run together.

## What the comparison showed

| Detector | False positives on 3,325 normal test windows | False-positive rate |
|---|---:|---:|
| Fixed threshold of five failed events | 0 | 0% |
| One-Class SVM | 22 | 0.662% |
| Isolation Forest | 31 | 0.932% |
| Random Forest | Campaign training pending | Unavailable |

Precision, recall, F1, ROC-AUC, PR-AUC and detection latency are part of the evaluation. Recall, F1, AUC and latency could not be measured without positive examples. The tests use clearly artificial examples to check that the code can train Random Forest, label A/B/C windows and calculate campaign metrics. The table measures the false-alarm workload for this offline dataset.

## Alerts and Wazuh

The output is one JSON line per alerted source window. It includes the timestamp, source when known, model, score, threshold, window bounds and leading feature explanations. The [results](../../src/ml/reports/results.md) include an actual emitted example and plots. Roshni can use the [Wazuh handoff](../../src/ml/README.md#wazuh-handoff-for-roshni) to test rule 100400 and add the ML fields to her dashboard. The alert file passed local schema validation. Live Wazuh ingestion remains pending.

## What the team needs next

Furqan's synchronized logs, run labels and evidence are needed to measure attack recall and latency for A, B and C. Real normal lab logs from Talha are needed to establish how often the detectors flag legitimate behavior. Roshni's Wazuh export will support a rule-versus-ML comparison over the same held-out period. The normal simulator lacked MQTT and network-flow measurements, and source-window analysis cannot infer service outages from silence alone. See the [design](ml_design.md) for how those limits affect interpretation.
