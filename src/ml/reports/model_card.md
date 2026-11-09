
# Model card

| Detector | Training and decision |
|---|---|
| Threshold baseline | Fixed rule at five failed events per 10-second source window. Score is the failure count and the stored threshold is 4.5 |
| One-Class SVM | StandardScaler and RBF kernel, `nu=0.01`. Negated decision function is the score |
| Isolation Forest | StandardScaler and 200 seeded trees. Negated sample score is the anomaly score |
| Random Forest | 200 seeded trees and balanced class weights. Flag positive class probability above 0.5. Training requires both classes and positive examples from at least two distinct runs by default |

The two anomaly models fit only clean benign training windows and subsample large training sets to 5,000 windows with seed 1. Their thresholds use the higher empirical quantile from an independent clean validation slice. The test slice is scored once per fixed candidate configuration. A target of 1% on validation can yield a different rate on later traffic.

Anomaly explanations rank how much the score falls when each feature is set to its normal training mean. Ties favor larger standardized deviations. If no individual replacement lowers the score, the explanation falls back to the largest nonzero deviations. This local approximation can miss interactions between features. Random Forest reports global feature importance. The threshold rule reports the feature it actually uses. These explanations help identify unusual measurements and have different meanings across models.

Isolation Forest can assign similar scores to values at and far beyond the edge of a repetitive training distribution, since those values can land in the same tree leaves. One-Class SVM can give high scores to behaviors absent from training, including legitimate maintenance or protocol changes. Evaluate both models on realistic look-alikes before using their scores for operational decisions.

Use only in the isolated synthetic lab. Treat alerts as triage signals. Model artifacts use joblib and require trusted inputs and a compatible Python scientific stack. The artifacts record the window length and source inventory used for training. See [results](results.md) for the measured operating points and [the dataset card](dataset_card.md) for coverage.
