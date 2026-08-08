FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        suricata iproute2 ethtool tcpdump python3-minimal ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY start_ids.sh /opt/ids/start_ids.sh
COPY alert_forward.py /opt/ids/alert_forward.py

CMD ["sleep", "infinity"]
