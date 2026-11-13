# Deploying Wazuh (task M3-01)

**Pinned tag: `v4.9.2`** (`wazuh/wazuh-manager`, `wazuh/wazuh-indexer`, `wazuh/wazuh-dashboard`,
`wazuh/wazuh-certs-generator:0.0.2`). Deployed, tested against real traffic, and documented for
this submission - see **[docs/report/evaluation.md](../../../../docs/report/evaluation.md)** for
the full writeup (what was found, what was fixed, actual alert counts).

Upstream is cloned into `src/detection/siem/deploy/wazuh-docker/`. **That whole folder is
git-ignored** (it's a vendor clone, and `internal_users.yml` holds password hashes) - which means,
important for anyone reproducing this, **the RailSOC-specific files are not inside it in git**.
They live in the tracked `src/detection/siem/deploy/overrides/` folder instead and get copied on
top of the clone (step 2 below):

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
- `.env.example` - a template for the credentials file (see "Credentials" below); **not** committed
  with real values, by design.

`config/wazuh_indexer/internal_users.yml` (the password hashes) is **not** in `overrides/` at all -
rotate it yourself following "Credentials" below, using the upstream clone's own demo file as the
starting point. Sharing one bcrypt hash across every clone of this repo defeats the point of
rotating it.

## Bring it up

```bash
# one-time, Windows/Docker Desktop (WSL2) - OpenSearch needs this
wsl -d docker-desktop sysctl -w vm.max_map_count=262144

# 1. clone upstream at the pinned tag
git clone --branch v4.9.2 https://github.com/wazuh/wazuh-docker.git src/detection/siem/deploy/wazuh-docker

# 2. apply the RailSOC overrides on top
cp -r src/detection/siem/deploy/overrides/* src/detection/siem/deploy/wazuh-docker/

cd src/detection/siem/deploy/wazuh-docker
cp .env.example .env    # fill in real values - see "Credentials" below
docker compose -f generate-indexer-certs.yml run --rm generator   # first time only
docker compose up -d

# 3. rotate the indexer/dashboard passwords away from the upstream demo values (see "Credentials")
```

Dashboard: `https://localhost` (self-signed cert - accept the browser warning), log in as `admin`
with whatever password you set in `.env` (see "Credentials" - this deployment's own password is
rotated from the upstream demo value and is not written down here). Indexer API:
`https://localhost:9200`. Manager
agent ports (1514/1515/514/55000) are also `127.0.0.1`-only; this deployment ingests via mounted
log files, not agents, so they are unused today but left for future agent enrolment.

## Credentials (HC-20)

`.env` (git-ignored) holds `INDEXER_PASSWORD`, `DASHBOARD_PASSWORD`, `API_PASSWORD`. All three have
been **rotated from the upstream quickstart defaults** (`SecretPassword` / `kibanaserver`) for this
submission - `config/wazuh_indexer/internal_users.yml` records that the `admin` and `kibanaserver`
hashes are the rotated ones, not the demo defaults.

`INDEXER_PASSWORD` and `DASHBOARD_PASSWORD` must always match whatever bcrypt hashes are actually
loaded into the live security index - changing `.env` alone does nothing on its own. To rotate them
for real (as was done here):

```bash
cd src/detection/siem/deploy/wazuh-docker

# 1. generate a new bcrypt hash for each user (inside the indexer container, which bundles its own JDK)
docker compose exec -e JAVA_HOME=/usr/share/wazuh-indexer/jdk wazuh.indexer \
  /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p '<new password>'

# 2. put the resulting hash into config/wazuh_indexer/internal_users.yml for that user
#    (admin and/or kibanaserver - both are bind-mounted straight into the container)

# 3. push the updated file into the LIVE security index (editing the YAML alone does not do this -
#    it is only read once, at first bootstrap)
docker compose exec -e JAVA_HOME=/usr/share/wazuh-indexer/jdk wazuh.indexer sh -c '
  /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
    -f /usr/share/wazuh-indexer/opensearch-security/internal_users.yml \
    -icl -nhnv \
    -cacert /usr/share/wazuh-indexer/certs/root-ca.pem \
    -cert /usr/share/wazuh-indexer/certs/admin.pem \
    -key /usr/share/wazuh-indexer/certs/admin-key.pem \
    -h localhost'

# 4. update .env to match, then recreate the manager + dashboard so they pick it up
echo 'INDEXER_PASSWORD=<new password>' # ...and DASHBOARD_PASSWORD, in .env
docker compose stop wazuh.manager wazuh.dashboard && docker compose up -d wazuh.manager wazuh.dashboard
```

The reserved `admin` user rejects password changes through the REST API
(`_plugins/_security/api/internalusers/admin` -> `403 Resource 'admin' is reserved`) -
`securityadmin.sh` is the correct tool, not the API. `API_PASSWORD` (the Wazuh manager's own WUI
API user) has no hash-file dependency and can be changed by editing `.env` and recreating the
manager alone.

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
