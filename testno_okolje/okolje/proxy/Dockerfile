ARG MITM_IMAGE=mitmproxy-quic:latest
FROM ${MITM_IMAGE}

RUN python3 -m venv /opt/p4venv \
    && /opt/p4venv/bin/pip install --no-cache-dir p4runtime-shell pyyaml

CMD ["sleep", "infinity"]
