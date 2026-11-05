import pytest

from railsoc_attacks.campaign import expand_sweep, run_campaign


def test_expand_sweep_is_a_cartesian_product_with_repeats():
    params = expand_sweep({"a": 1}, {"rate_per_s": [1, 5], "duration_s": [10, 20]}, repeats=2)
    assert len(params) == 8
    assert all(p["a"] == 1 for p in params)
    assert {p["rate_per_s"] for p in params} == {1, 5}
    assert {p["duration_s"] for p in params} == {10, 20}


def test_no_sweep_just_repeats_the_base():
    assert expand_sweep({"a": 1}, {}, repeats=3) == [{"a": 1}] * 3


def test_campaign_size_is_limited():
    with pytest.raises(ValueError, match="limit"):
        expand_sweep({}, {"x": list(range(100))})


def test_dry_run_campaign_creates_unique_run_ids_and_no_ground_truth(
    tmp_path, noop_cls, scope, t0
):
    results = run_campaign(
        noop_cls(),
        {"rate_per_s": [1, 2, 3]},
        repeats=2,
        evidence_dir=tmp_path / "ev",
        ground_truth_csv=tmp_path / "gt.csv",
        scope=scope,
        clock=lambda: t0,
    )
    ids = [r.run.run_id for r in results]
    assert len(ids) == 6 and len(set(ids)) == 6
    assert all(r.dry_run for r in results)
    assert not (tmp_path / "gt.csv").exists()
