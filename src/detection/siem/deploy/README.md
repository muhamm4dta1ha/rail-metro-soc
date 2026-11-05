# Deploying Wazuh (task M3-01)

We use **Wazuh** (single node: manager + indexer + dashboard) as the SIEM - the brief allows Wazuh or Splunk (HC-05). Use the official `wazuh/wazuh-docker` repository, **pinned to one release tag** that the whole team uses (record the tag at the top of this README).

Do not copy upstream compose files into this repo (they drift). Clone upstream into `src/detection/siem/deploy/wazuh-docker/` (git-ignored) and keep only our overrides here.

## Outline (verify against the upstream docs for your pinned tag)

1. Clone `wazuh/wazuh-docker`, check out the pinned tag, `cd single-node`.
2. Generate the indexer certificates (upstream `generate-indexer-certs.yml`).
3. `docker compose up -d`; open the dashboard on `https://localhost` (publish only on `127.0.0.1`).
4. **Change the default credentials** and store them in a local, git-ignored `.env` (HC-20).
5. Attach the manager to the lab's `soc_mgmt` network so lab assets can ship logs to it. Lab networks stay `internal: true`; only the dashboard gets an extra, host-facing network (HC-18).
6. Enrol agents (jump host, PIS) and add `localfile` entries for the JSON event logs (`src/detection/siem/ossec/`).
7. Copy `src/detection/siem/rules/*.xml` and `decoders/*.xml` into the manager's `etc/rules` / `etc/decoders`, restart, and test with `wazuh-logtest`.

## Windows / Docker Desktop gotchas

- The indexer needs `vm.max_map_count >= 262144`. On Docker Desktop (WSL2): `wsl -d docker-desktop sysctl -w vm.max_map_count=262144` (resets on restart; to persist, set it via `kernelCommandLine` in `%UserProfile%\.wslconfig`).
- Wazuh is memory hungry: give Docker/WSL2 at least 6-8 GB and stop other stacks while it runs. Record the measured usage here.
- If the laptop cannot run the lab and Wazuh together, run Wazuh on a teammate's machine or a VM and ship logs over the `soc_mgmt` network equivalent.
