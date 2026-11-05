# GitHub setup (one time, by Talha)

Everything here is done **by a person in the browser or terminal**. No AI assistant pushes code, opens PRs or is added as a collaborator (HC-15).

## 1. Create the repository
- Name: **`rail-metro-soc`** (alternatives: `railguard-soc`, `metro-soc-lab`, `trackwatch-soc`).
- Visibility: private while the work is in progress. Do **not** add a README, licence or `.gitignore` (the scaffold already has them).
- Description: *Domain-specific SOC for railway and metro systems: simulated lab, controlled attack scenarios, Wireshark/Wazuh detection and an ML detector (lab-only, synthetic data).*
- Topics: `soc`, `siem`, `wazuh`, `wireshark`, `ics-security`, `railway-security`, `machine-learning`, `anomaly-detection`, `docker`.
- Add **Furqan, Roshni and Anum** as collaborators (Write role). Never add an AI account.

## 2. First push (from `soc/rail-metro-soc/`)

```bash
git init -b main
git add .
git status
git commit -m "chore: initial scaffold (plan, contracts, module starters, CI)"
git remote add origin https://github.com/<OWNER>/rail-metro-soc.git
git push -u origin main
git switch -c develop
git push -u origin develop
```

Check `git status` before committing: no `.env`, no `.pcap`, no data or models should be listed (the `.gitignore` blocks them). The commit message has **no** co-author or "generated with" line.

## 3. Branches and default branch
- Settings -> Branches -> default branch = **`develop`** (new PRs then target `develop` by default).
- Settings -> General -> Pull Requests: allow squash merging and merge commits; tick "Automatically delete head branches".

## 4. Protect `develop` and `main` (Settings -> Branches -> Add rule)

| Setting | `develop` | `main` |
|---|---|---|
| Require a pull request before merging | yes, **1** approval | yes, **2** approvals |
| Dismiss stale approvals when new commits are pushed | yes | yes |
| Require status checks to pass | **`ci-gate`** | **`ci-gate`** |
| Require branches to be up to date | yes | yes |
| Require conversation resolution | yes | yes |
| Require review from Code Owners | after CODEOWNERS is filled in | after CODEOWNERS is filled in |
| Restrict pushes / allow force pushes / allow deletions | block all | block all |
| Apply to administrators too | yes | yes |

The status check `ci-gate` only appears in the list after CI has run once: open a first PR (for example a tiny docs change on a `docs/docs/...` branch), let CI finish, then add the check to both rules.

**Free plan note:** on a free personal account GitHub only offers branch protection for *public* repositories; private repositories need GitHub Pro (students can get it through the GitHub Student Developer Pack) or an organisation plan. Check what Settings -> Branches shows. If protection is unavailable, follow the same rules by discipline - CI still runs and shows red/green on every PR.

## 5. CODEOWNERS
Edit `.github/CODEOWNERS`: replace the `<...>` placeholders with the real usernames and uncomment the lines (review ring: Talha <- Roshni, Furqan <- Talha, Roshni <- Anum, Anum <- Furqan).

## 6. Day-to-day
- New work: `git switch develop && git pull && git switch -c feature/<module>/<TASK-ID>-<slug>`.
- Before pushing: `python scripts/check_all.py`.
- PR link: `python scripts/pr_link.py` (current branch), `--all` (every branch ahead of `develop`), `--release` (`develop` -> `main`). The script only prints a link; open it yourself.
- Release: when a milestone gate in `plan/PLAN.md` section 8 is met, Talha opens the release PR, two people approve, merge with a merge commit, then tag: `git tag -a v0.2 -m "Phase 1 gate" && git push origin v0.2`.
