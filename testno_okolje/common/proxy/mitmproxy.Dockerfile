FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 iptables ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/mitmproxy

COPY pyproject.toml MANIFEST.in README.md LICENSE ./
COPY mitmproxy ./mitmproxy

RUN pip install --no-cache-dir .

EXPOSE 8080 8081

CMD ["sleep", "infinity"]
