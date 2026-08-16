FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates python3-minimal python3-yaml iproute2 \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONPATH=/opt/traffic/client PYTHONUNBUFFERED=1

CMD ["sleep", "infinity"]
