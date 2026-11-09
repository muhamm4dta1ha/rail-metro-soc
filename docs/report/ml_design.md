
# Module 4 | Machine learning threat detection

**Owner** Anum Ali · **Reviewer** Furqan

The detector flags unusual activity in the isolated railway SOC lab. Scenario A can appear as bursts of failed administrative logins. Scenario B can alter Modbus writes, MQTT connects and the mix of destinations. Scenario C can increase HTTP errors and latency, or change the volume of service and flow logs. A single alert means a source window passed a threshold. Analysts use the surrounding logs and Module 3 rules to investigate.

## Data and training

Talha's schema-valid JSONL logs enter the pipeline alongside Furqan's separate CSV of campaign runs. Events are binned by source and UTC time. The shared labeling contract identifies direct attack activity and victim impact. The dataset keeps those labels separate and preserves normal `BASELINE` IDs. Training, calibration and test slices follow time. Every source at a timestamp and every ground-truth run span stays on one side of each cut. Anomaly fit and calibration also exclude unrelated activity in campaign-time windows.

Behavior features include authentication failures, HTTP traffic and latency, destination diversity, Modbus commands, MQTT activity, flow totals and selected telemetry summaries. The fixed comparison rule flags five failures in a 10-second window. One-Class SVM and Isolation Forest learn from normal training windows and set separate score thresholds using clean validation windows and a 1% window false-positive target. Random Forest uses balanced class weights and needs labeled threat windows from distinct training runs. The default supervised positive class includes direct activity and victim impact.

## Evaluation and handoff

The test slice is used to measure confusion counts, precision, recall, F1, false-positive rate, ROC-AUC, average precision and false alerts per hour. The same Module 3 evaluator measures run detections and latency from `ml.alert` timestamps and optional Wazuh rule exports. A window can produce at most one alert per source and model. Alerts carry the score, threshold, window bounds and feature explanations. Roshni can monitor the JSONL stream using Wazuh's JSON decoder and the existing rule 100400.

See the [results and example alert](../../src/ml/reports/results.md), [dataset card](../../src/ml/reports/dataset_card.md), [feature catalogue](../../src/ml/reports/feature_catalogue.md), [model card](../../src/ml/reports/model_card.md) and [PowerShell and Wazuh instructions](../../src/ml/README.md).

## Limits

This delivery has a measured normal-only dry run and artificial test fixtures. Campaign detection for A, B and C requires Furqan's real lab evidence and normal look-alikes from Talha. Source grouping may dilute a distributed attack across multiple rows. Traffic silence needs a separate expected-activity signal, such as periodic health events. When campaign logs arrive, preserve the holdout, inspect false positives by source and use the rule comparison on a synchronized export. A later shift in traffic patterns requires fresh validation before reusing the operating threshold.
