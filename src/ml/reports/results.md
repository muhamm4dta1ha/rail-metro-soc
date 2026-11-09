
# Held-out results | offline normal simulation

The source data were 66,985 generated events from 2026-01-05 00:00–12:00 UTC, using seed 1. Dataset V1 contains 8,884 benign source windows. We fit on 2,788 windows before 06:00 UTC, calibrated on 2,771 windows from 06:00 to 08:24 UTC, and tested on 3,325 windows from 08:24 to 12:00 UTC. The test span contains 1,223 occupied 10-second time bins, or 3.3972 observed hours. Counts and rates below use that held-out slice. The test set did not determine the thresholds.

| Detector | Score threshold | True negatives | False positives | Validation FPR | Test FPR | False alarms / observed hour |
|---|---:|---:|---:|---:|---:|---:|
| Five-failure rule | 4.5 | 3,325 | 0 | Fixed rule | 0% | 0.00 |
| One-Class SVM | 0.149319 | 3,303 | 22 | 0.974% | 0.662% | 6.48 |
| Isolation Forest | 0.703412 | 3,294 | 31 | 0.974% | 0.932% | 9.13 |

The anomaly models both produced 27 false positives on validation at a 1% target. On test, precision was zero for the two models that flagged benign windows and unavailable for the fixed rule because it flagged none. The two positive confusion cells were zero for every model because there were no positive labels. Recall, F1, ROC-AUC, PR-AUC, per-scenario recall and detection latency were unavailable. Random Forest was exercised in the artificial multi-scenario test fixture and skipped for the measured run because there were zero campaign labels. A Wazuh rule comparison requires Roshni's aligned rule export and Furqan's recorded runs.

### False-positive examples

- One-Class SVM's high-scoring `10.60.10.22` window at 09:16:20 UTC had one HTTP 4xx and one failed event out of three. Its `10.60.10.23` window at 11:02:50 UTC had one HTTP 5xx with a recorded latency of 821.4 ms. Both were benign generator behavior.
- Isolation Forest's highest-scoring window was `10.60.10.23` at 08:56 UTC. It contained three HTTP requests, a mean latency of 36.5 ms and zero failures. Its most prominent score explanations included HTTP request rate and the number of latency samples.
- `10.60.10.23`, the engineering workstation, had the most false positives under both anomaly models. It accounted for 5 of 22 One-Class SVM alerts and 8 of 31 Isolation Forest alerts.
- The fixed rule had no false positives on these inputs. With only benign examples, these results cannot establish which detector is better at finding attacks. Isolation Forest also has limited resolution beyond the training range when normal traffic repeats a few patterns.

### Schema-valid alert example

This line came from the held-out One-Class SVM output. It flags a benign window and is suitable for a lab ruleset smoke test.

```json
{"@timestamp":"2026-01-05T08:24:30.000Z","event":{"dataset":"ml.alert","category":"intrusion_detection","action":"anomaly_detected","outcome":"unknown"},"host":{"name":"ml-detector"},"source":{"ip":"10.60.30.22"},"ml":{"model":"ocsvm","score":2.0750674416456647,"threshold":0.14931923325003904,"window_start":"2026-01-05T08:24:20.000Z","window_end":"2026-01-05T08:24:30.000Z","top_features":["n_http_latency_samples","http_requests_per_s","n_unique_dst_ip"]},"message":"anomalous activity from 10.60.30.22 in a 10s window"}
```

The full 12-hour One-Class SVM replay produced 58 schema-valid alerts. Batch and incremental output were byte-for-byte identical. The Module 3 evaluator read that file and reported 58 false alarms, or 4.83 per elapsed simulated hour. This replay includes train and validation periods and is separate from the held-out comparison.

[Generated comparison table](generated/comparison.md) · [JSON metrics](generated/metrics.json) · [False-positive chart](generated/false_positives.png) · [Confusion matrices](generated/confusion_matrices.png)

Regenerate the local artifacts with `python -m railsoc_ml.cli compare`. Versions for this run were Python 3.11.9, NumPy 2.4.6, pandas 3.1.1, scikit-learn 1.9.1, joblib 1.6.0 and matplotlib 3.11.2.
