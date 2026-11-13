# Deploying Wazuh (task M3-01)

**Pinned tag: `v4.9.2`** (`wazuh/wazuh-manager`, `wazuh/wazuh-indexer`, `wazuh/wazuh-dashboard`,
`wazuh/wazuh-certs-generator:0.0.2`). Deployed, tested against real traffic, and documented for
this submission - see **[docs/report/evaluation.md](../../../../docs/report/evaluation.md)** for
the full writeup (what was found, what was fixed, actual alert counts).

Upstream is cloned into `src/detection/siem/deploy/wazuh-docker/` (git-ignored, per `.gitignore`)
with RailSOC's own overrides layered on top in this same folder:

- `docker-compose.yml` - every published port bound to `127.0.0.1:` only (HC-18); credentials
  read from a local `.env` (HC-20, see below); `lab/data/raw` mounted read-only into the manager;
  our `rules/`, `decoders/` and a **patched index template** mounted in.
- `config/wazuh_cluster/wazuh_manager.conf` - `<localfile>` entries for the real event logs
  (`pis_app.jsonl`, `modbus_live.jsonl`, `ssh_live.jsonl`, `attack_modbus_events.jsonl`,
  `ml_alerts.jsonl`).
- `config/wazuh_cluster/wazuh-template-railsoc-fixed.json` - the stock filebeat index template
  with `data.url` corrected from `keyword` to an object (`{"path": keyword}`). **Why:** this
  project's event schema defines `url` as an object; the stock Wazuh template assumes it's a flat
  string, so every HTTP-based alert (scenario A and C) failed to index until this was fixed - see
  evaluation.md section 4 for the exact error and how it was found.

## Bring it up

```bash
# one-time, Windows/Docker Desktop (WSL2) - OpenSearch needs this
wsl -d docker-desktop sysctl -w vm.max_map_count=262144

cd src/detection/siem/deploy/wazuh-docker
cp .env.example .env    # if starting fresh - see "Credentials" below for what must stay as-is
docker compose -f generate-indexer-certs.yml run --rm generator   # first time only
docker compose up -d
```

Dashboard: `https://localhost` (self-signed cert - accept the browser warning), log in
`admin` / `SecretPassword` (see "Credentials"). Indexer API: `https://localhost:9200`. Manager
agent ports (1514/1515/514/55000) are also `127.0.0.1`-only; this deployment ingests via mounted
log files, not agents, so they are unused today but left for future agent enrolment.

## Credentials (HC-20)

`.env` (git-ignored) holds `INDEXER_PASSWORD`, `DASHBOARD_PASSWORD`, `API_PASSWORD`.
**`INDEXER_PASSWORD` and `DASHBOARD_PASSWORD` must stay `SecretPassword` / `kibanaserver`** (the
upstream quickstart defaults) - they are tied to bcrypt hashes already baked into
`config/wazuh_indexer/internal_users.yml` by the certs-generator step; changing the env var without
regenerating that hash breaks indexer auth. `API_PASSWORD` has no such constraint and was changed
from the upstream default. Rotating the indexer credentials for real would mean using the
indexer's own hashing tool to regenerate `internal_users.yml` - not done here, flagged as a real
gap for anything beyond a `127.0.0.1`-only lab.

## Ingesting logs

This deployment ingests by mounting `lab/data/raw` read-only into the manager and configuring
`<localfile log_format="json">` per source file (see `wazuh_manager.conf`) - simpler than agent
enrolment for a single-host lab, and what task M3-02's "simple log-forwarder" option in
`plan/DAY1_PLAN.md` describes. One important operational finding: **a `docker restart` of the
manager does not make `wazuh-logcollector` re-open a log file whose inode changed** (e.g. after
deduplicating a replayed file) - use `docker compose stop` + `up` (a full recreate) instead.

## Windows / Docker Desktop gotchas

- `vm.max_map_count >= 262144` (above) - resets on a WSL2 restart; persist it via
  `kernelCommandLine` in `%UserProfile%\.wslconfig` if you don't want to repeat this.
- Wazuh is memory hungry: give Docker/WSL2 at least 6-8 GB. Measured here: manager + indexer +
  dashboard idled around 2-2.5 GB combined on top of the simulation lab's own containers; fine
  alongside the lab on one machine with Docker Desktop's defaults.
- A self-signed cert means any API/CLI client (`curl`, this repo's own tooling) needs `-k` /
  `verify=False` against `https://localhost:9200` and `:443`.
