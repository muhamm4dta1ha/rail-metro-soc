## What and why
<!-- One or two sentences. Link the task id(s) from plan/PLAN.md, e.g. M1-04. -->

Task id(s):
Module: <!-- sim | attacks | detection | ml | common | docs | ci -->
Branch: `feature/<module>/<TASK-ID>-<slug>` into `develop`

## How it was tested
- [ ] `python scripts/check_all.py` is green on my machine
- [ ] New or changed behaviour has tests in the module's `tests/` folder
- Commands, screenshots or evidence:

## Checklist (hard constraints - plan/PLAN.md section 2)
- [ ] Lab-only and synthetic: nothing targets real or operational systems, no real data (HC-02, HC-03)
- [ ] Events follow `docs/contracts/event_schema.md`; labels only in the ground truth (HC-19)
- [ ] No secrets, no files over 10 MB, no pcaps / datasets / models in git (HC-20)
- [ ] Docs updated (module README or `docs/`), and the plan if the scope changed
- [ ] Contract change (`src/common/`, `docs/contracts/`)? Owner and one consumer must approve

## Review
Reviewer (ring): <!-- Talha's PRs -> Roshni | Furqan's -> Talha | Roshni's -> Anum | Anum's -> Furqan -->
