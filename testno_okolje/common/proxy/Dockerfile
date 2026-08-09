FROM mitmproxy/mitmproxy:latest

USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 iptables tcpdump \
    && rm -rf /var/lib/apt/lists/*

COPY sni_passthrough.py /opt/proxy/sni_passthrough.py
COPY content_block.py /opt/proxy/content_block.py
COPY controller_bypass.py /opt/proxy/controller_bypass.py
COPY proxy_stats.py /opt/proxy/proxy_stats.py

ENTRYPOINT []

CMD ["sleep", "infinity"]
