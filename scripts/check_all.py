#!/usr/bin/env python3
"""Run the same gates as CI locally: lint, tests and compose validation.

  python scripts/check_all.py

Run this before you push a branch / open a PR. Exit code != 0 means CI would fail too.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(name: str, cmd: list[str]) -> bool:
    print(f"\n=== {name}: {' '.join(cmd)}")
    return subprocess.run(cmd, cwd=ROOT, check=False).returncode == 0


def main() -> int:
    steps: list[tuple[str, list[str]]] = [
        ("lint (ruff)", [sys.executable, "-m", "ruff", "check", "."]),
        ("tests (pytest)", [sys.executable, "-m", "pytest", "-q"]),
    ]
    if shutil.which("docker"):
        steps.append(
            (
                "compose config",
                [
                    "docker",
                    "compose",
                    "-f",
                    "src/simulation/docker-compose.yml",
                    "--env-file",
                    "src/simulation/.env.example",
                    "config",
                    "-q",
                ],
            )
        )
    else:
        print("docker not found: skipping 'compose config' (CI will still run it)")

    results = {name: run(name, cmd) for name, cmd in steps}
    print("\n=== summary")
    for name, ok in results.items():
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
