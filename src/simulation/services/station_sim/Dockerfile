# Build context is the repository root (see src/simulation/docker-compose.yml).
# Real Modbus/TCP server (HC-23 fallback for OpenPLC - see docs/architecture/architecture.md).
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
COPY src/simulation/railsoc_sim ./railsoc_sim

RUN pip install --no-cache-dir pymodbus

RUN useradd --system --no-create-home railsoc
USER railsoc

EXPOSE 502
CMD ["python", "-m", "railsoc_sim.services.station_plc"]
