from datetime import UTC, datetime, timedelta, timezone

import pytest

from railsoc_common.ids import is_run_id, new_run_id


def test_run_id_format_and_roundtrip():
    run_id = new_run_id("A", datetime(2026, 11, 5, 9, 14, 3, tzinfo=UTC), seq=1)
    assert run_id == "RUN-A-20261105T091403Z-01"
    assert is_run_id(run_id)


def test_run_id_converts_to_utc():
    plus_two = timezone(timedelta(hours=2))
    assert new_run_id("C", datetime(2026, 1, 1, 2, 0, 0, tzinfo=plus_two)) == "RUN-C-20260101T000000Z-01"


def test_run_id_rejects_bad_input():
    with pytest.raises(ValueError):
        new_run_id("D")
    with pytest.raises(ValueError):
        new_run_id("A", seq=100)
    assert not is_run_id("RUN-A-2026-01")
    assert not is_run_id("run-a-20261105T091403Z-01")
