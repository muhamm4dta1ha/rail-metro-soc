# Build context is the repository root (see src/simulation/docker-compose.yml).
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
COPY src/common/railsoc_common ./railsoc_common
COPY src/simulation/railsoc_sim ./railsoc_sim

RUN useradd --system --no-create-home railsoc
USER railsoc

EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
  CMD python -c "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2).status == 200 else 1)"

CMD ["python", "-m", "railsoc_sim.pis_stub"]
