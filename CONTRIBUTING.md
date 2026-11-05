# Contributing

Team: **Talha** (M1 simulation, repo admin), **Furqan** (M2 attacks), **Roshni** (M3 detection), **Anum** (M4 ML). The hard constraints are in [plan/PLAN.md](plan/PLAN.md) section 2; this page is the short version of how to work with them.

## 1. Set up

```bash
git clone https://github.com/<OWNER>/rail-metro-soc.git
cd rail-metro-soc
python -m venv .venv
source .venv/bin/activate        # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -e ".[dev,ml]"       # drop ",ml" if you only touch simulation, attacks or detection
python scripts/check_all.py
```

## 2. The flow for every change (HC-14)

1. `git switch develop && git pull`
2. `git switch -c feature/<module>/<TASK-ID>-<slug>` - for example `feature/sim/M1-04-pis-service`.
   Prefixes: `feature`, `fix`, `docs`, `chore`, `test`. Modules: `common`, `sim`, `attacks`, `detection`, `ml`, `docs`, `ci`, `repo`.
3. Write the code **and its tests** (the module's `tests/` folder).
4. `python scripts/check_all.py` must be green.
5. `git push -u origin <branch>`, then `python scripts/pr_link.py` prints the PR link - open it in the browser.
6. The reviewer approves, CI is green, squash-merge into `develop`.

Never commit directly to `develop` or `main`. `main` only receives `develop` through a release PR (`python scripts/pr_link.py --release`).

## 3. Who reviews whom

Talha <- Roshni - Furqan <- Talha - Roshni <- Anum - Anum <- Furqan. Changes in `src/common/` or `docs/contracts/` are **contract changes**: the owner (Talha for events, Furqan for ground truth) and at least one consumer approve, and code, doc and tests change together.

## 4. Commits and PRs

- Conventional Commits with the module as scope: `feat(sim): M1-04 PIS login events`, `fix(ml): leak in split`, `docs(plan): add handoffs`.
- **No AI co-author or "generated with" lines, in commits or PR text (HC-15).** CI rejects them. AI assistants may help you write code locally, but they never push, never open PRs and are never listed as contributors; the PR link comes from `scripts/pr_link.py`, and a person opens it.
- Fill in the PR template honestly; tick only what you checked.

## 5. What must never be committed (HC-20)

Secrets (`.env`, keys), pcaps, generated datasets, trained models, archives, virtual environments, files over 10 MB. Use `.env.example` files for settings; keep big files outside git and list them in `lab/evidence/EXTERNAL_FILES.md`.

## 6. Safety (HC-02, HC-03, HC-18, HC-22)

Lab-only, synthetic-only. Attack code calls `ctx.guard(ip)` before any traffic, never targets anything outside `10.60.0.0/16`, never touches safety-related railway functions, and respects the caps and the kill switch in `src/attacks/config/lab_scope.toml`.
