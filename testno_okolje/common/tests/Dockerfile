FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3-minimal python3-yaml python3-pytest \
    && rm -rf /var/lib/apt/lists/*

COPY client/runner/ /opt/runner/
COPY tests/ /opt/tests/

ENV PYTHONPATH=/opt PYTHONUNBUFFERED=1 TRAFFIC_ROOT=/opt/traffic

CMD ["python3", "-m", "pytest", "-q", "/opt/tests"]
