FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates python3-minimal python3-yaml iproute2 tcpdump procps \
    && rm -rf /var/lib/apt/lists/*

COPY runner/ /opt/runner/

ENV PYTHONPATH=/opt PYTHONUNBUFFERED=1

CMD ["sleep", "infinity"]
