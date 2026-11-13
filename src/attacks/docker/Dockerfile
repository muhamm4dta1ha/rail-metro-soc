# Build context is the repository root (see lab/ops/docker-compose.evidence.yml).
# Fills the M2-03 "attacker tooling image" placeholder: a real container that runs the
# railsoc_attacks scenario runners (HC-23 - genuine HTTP/Modbus client calls, no fabricated
# events). Added by Roshni (M3) to generate real evidence for detection; Furqan should review
# and move/rename under src/attacks if this becomes the permanent M2-03 artifact.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
COPY src/common/railsoc_common ./railsoc_common
COPY src/attacks/railsoc_attacks ./railsoc_attacks
COPY src/attacks/config ./config

RUN pip install --no-cache-dir jsonschema pymodbus

CMD ["sh", "-c", "echo 'attacker tooling ready; use: docker compose exec attacker python -m railsoc_attacks.cli ...'; sleep infinity"]
