"""Campaign runner (starter for M2-10): many parameterised runs so Module 4 gets enough varied data.

Dry-run by default. ML needs variety (rate, duration, source, time of day) and volume (target:
>= 10 runs per scenario), not one lucky demo.
"""

from __future__ import annotations

import itertools
from typing import Any

from railsoc_attacks.recorder import RunResult, run_scenario
from railsoc_attacks.scenario import ScenarioBase

MAX_RUNS = 99  # run ids carry a 2-digit sequence number


def expand_sweep(
    base: dict[str, Any],
    sweep: dict[str, list[Any]],
    repeats: int = 1,
    max_runs: int = MAX_RUNS,
) -> list[dict[str, Any]]:
    """Cartesian product of the sweep values, each repeated `repeats` times."""
    keys = sorted(sweep)
    combos = list(itertools.product(*(sweep[key] for key in keys))) or [()]
    params = [
        {**base, **dict(zip(keys, combo, strict=True))} for combo in combos for _ in range(repeats)
    ]
    if len(params) > min(max_runs, MAX_RUNS):
        raise ValueError(f"campaign has {len(params)} runs; the limit is {min(max_runs, MAX_RUNS)}")
    return params


def run_campaign(
    scenario: ScenarioBase,
    sweep: dict[str, list[Any]] | None = None,
    *,
    repeats: int = 1,
    base: dict[str, Any] | None = None,
    dry_run: bool = True,
    **kwargs: Any,
) -> list[RunResult]:
    """Run every parameter combination through run_scenario (guarded, recorded)."""
    results = []
    for seq, params in enumerate(expand_sweep(base or {}, sweep or {}, repeats), start=1):
        results.append(run_scenario(scenario, params, dry_run=dry_run, seq=seq, **kwargs))
    return results
