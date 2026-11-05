# rail-metro-soc

A domain-specific **Security Operations Center (SOC) for railway and metro systems**: a simulated lab, three controlled attack scenarios, Wireshark + Wazuh detection and a machine-learning detector that works with all of them.

> **Lab-only and synthetic.** Nothing here may ever be connected to operational signaling or any real railway, metro or utility network. The full list of hard constraints is in [plan/PLAN.md](plan/PLAN.md) section 2.

## Team

| Person | Module | Folder | Reviewer |
|---|---|---|---|
| **Talha** | M1 Simulation & Architecture, repo admin | [`src/simulation/`](src/simulation/README.md) | Roshni |
| **Furqan** | M2 Attack Generation | [`src/attacks/`](src/attacks/README.md) | Talha |
| **Roshni** | M3 Detection (Wireshark + SIEM) | [`src/detection/`](src/detection/README.md) | Anum |
| **Anum** | M4 ML Threat Detection | [`src/ml/`](src/ml/README.md) | Furqan |

## Layout

```
plan/PLAN.md        the plan: hard constraints, who does what, tasks, roadmap
src/                all code, one folder per module (+ common/ = shared contracts)
docs/               architecture, protocols, contracts, report, GitHub setup
lab/                evidence, ground truth, generated data (data/ is not in git)
tests/ scripts/     repo-level tests and tooling (PR links, policy checks, local CI)
.github/            CI workflow, PR template, CODEOWNERS
```

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate        # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -e ".[dev,ml]"
python scripts/check_all.py      # lint + tests + compose validation (what CI runs)
```

Generate sample normal traffic and look at the asset inventory:

```bash
python -m railsoc_sim.cli generate --hours 2 --seed 1 --out lab/data/raw/normal_s1.jsonl
python -m railsoc_sim.cli assets
```

## How we work

Branches `main` (release) and `develop` (integration). Every change: own branch `feature/<module>/<TASK-ID>-<slug>` -> pull request into `develop` -> CI green + review -> merge. Read [CONTRIBUTING.md](CONTRIBUTING.md) before your first branch and [docs/github_setup.md](docs/github_setup.md) for the one-time repository setup.
