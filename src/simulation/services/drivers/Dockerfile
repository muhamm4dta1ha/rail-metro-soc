# Build context is the repository root (see src/simulation/docker-compose.yml).
# Runs the real HTTP/Modbus/SSH client drivers (HC-23) - today's unified stand-in for
# OCC-01's poller role and WS-03's maintenance-write/SSH role (see plan/DAY1_PLAN.md).
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
COPY src/common/railsoc_common ./railsoc_common
COPY src/simulation/railsoc_sim ./railsoc_sim
COPY src/simulation/config ./config

RUN pip install --no-cache-dir jsonschema requests pymodbus paramiko

# Runs as root (unlike pis): it only makes outbound connections to our own lab services, and
# it writes JSONL logs to a host-mounted volume where a fixed non-root UID would fight bind-mount
# permissions for no real security benefit here.
CMD ["python", "-m", "railsoc_sim.scripts.run_normal_day"]
