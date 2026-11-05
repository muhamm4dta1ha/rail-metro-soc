# lab/evidence - proof for every attack run

**Owners: Furqan** (attack evidence) and **Roshni** (Wireshark and SIEM evidence).

```
runs/<run_id>/        manifest.json, log slices, alert exports, screenshots   (written by the recorder, M2-08)
runs/dry_runs/        scratch manifests from dry runs - git-ignored
baseline/             matching normal-activity windows (M2-07)
samples/              SMALL pcap/log samples (<= 5 MB each) that are allowed in git
EXTERNAL_FILES.md     list of big files kept outside git, with link and sha256
```

Pcaps are git-ignored everywhere except `samples/` (HC-20). Every claim in the report points to a file here (HC-07).
