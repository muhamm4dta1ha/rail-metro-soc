import pytest

from railsoc_ml.dataset import build_dataset
from railsoc_ml.models import AnomalyDetector, SupervisedDetector, ThresholdBaseline


@pytest.fixture(scope="module")
def data(stream):
    events, runs = stream
    return build_dataset(events, runs)


def fitted(data, **kwargs):
    normal = data[data["run_id"] == ""]
    model = AnomalyDetector(seed=1, **kwargs).fit(normal)
    model.calibrate(normal, target_fpr=0.01)
    return model


def test_anomaly_detector_flags_the_attack_windows_and_few_normal_ones(data):
    model = fitted(data)
    assert model.name == "ocsvm"
    flagged = model.predict(data)
    assert flagged[data["is_attack"].to_numpy() == 1].all()
    assert flagged[(data["run_id"] == "").to_numpy()].mean() <= 0.05


def test_predict_requires_calibration(data):
    normal = data[data["run_id"] == ""]
    with pytest.raises(RuntimeError, match="calibrate"):
        AnomalyDetector(seed=1).fit(normal).predict(data)


def test_isolation_forest_option_trains_scores_and_explains(data):
    # Kept for comparison only: on this very regular traffic it cannot extrapolate beyond the
    # training range (see the AnomalyDetector docstring), so no detection claim is made here.
    model = fitted(data, method="isolation_forest")
    assert model.name == "isolation_forest"
    scores = model.score(data)
    assert len(scores) == len(data) and (scores == scores).all()
    assert model.predict(data).shape == (len(data),)
    assert model.explain(data.iloc[0])


def test_unknown_method_is_rejected():
    with pytest.raises(ValueError, match="method must be one of"):
        AnomalyDetector(method="magic")


def test_very_large_training_sets_are_subsampled(data):
    normal = data[data["run_id"] == ""]
    model = AnomalyDetector(seed=1, max_train=50).fit(normal)
    assert model.scaler.n_samples_seen_ == 50


def test_explain_points_at_the_failure_features(data):
    model = fitted(data)
    row = data[data["is_attack"] == 1].iloc[0]
    assert {"n_failures", "n_http_4xx", "n_events"} & set(model.explain(row, top_k=3))


def test_save_and_load_give_identical_scores(data, tmp_path):
    model = fitted(data)
    path = tmp_path / "models" / "anomaly.joblib"
    model.save(path)
    loaded = AnomalyDetector.load(path)
    assert (loaded.score(data) == model.score(data)).all()
    assert loaded.threshold == model.threshold


def test_threshold_baseline_flags_failure_bursts_only(data):
    baseline = ThresholdBaseline(min_failures=5)
    flagged = baseline.predict(data)
    assert flagged[data["is_attack"].to_numpy() == 1].all()
    assert not flagged[(data["run_id"] == "").to_numpy()].any()


def test_supervised_detector_separates_the_known_attack_in_its_training_data(data):
    model = SupervisedDetector(seed=1).fit(data, data["is_attack"])
    scores = model.score(data)
    assert scores[data["is_attack"].to_numpy() == 1].min() > model.threshold
    assert scores[(data["run_id"] == "").to_numpy()].max() <= model.threshold
    assert model.explain(data.iloc[0])


def test_supervised_detector_without_attacks_scores_zero(data):
    benign = data[data["run_id"] == ""]
    model = SupervisedDetector(seed=1).fit(benign, benign["is_attack"])
    assert (model.score(data) == 0).all()
