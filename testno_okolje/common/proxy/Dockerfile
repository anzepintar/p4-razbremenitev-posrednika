FROM mitmproxy/mitmproxy:latest

USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 iptables tcpdump \
    && rm -rf /var/lib/apt/lists/*

COPY sni_passthrough.py /opt/proxy/sni_passthrough.py

ENTRYPOINT []

CMD ["sleep", "infinity"]
