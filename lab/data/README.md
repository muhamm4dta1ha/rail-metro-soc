# lab/data - generated datasets (not in git)

Everything in this folder except this README is git-ignored (HC-20). Typical contents:

- `raw/` - event streams from the generator or the lab (JSON Lines), e.g. `normal_s1.jsonl`;
- `processed/` - labelled windows (`dataset_v1.csv`), ML alerts (`ml_alerts.jsonl`).

Rebuild instead of sharing: the generator and the ML CLI are seeded, so the same command gives the same data (HC-21). Share large files outside git and list them with checksums in `lab/evidence/EXTERNAL_FILES.md`.
