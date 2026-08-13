# Osnova je fork mitmproxy (05-MITMPROXY-FORK), ki v transparentnem nacinu prestreze
# tudi QUIC/HTTP-3. Sliko zgradi build.sh, glej clab/Dockerfile.mitmproxy v forku.
ARG MITM_IMAGE=mitmproxy-quic:latest
FROM ${MITM_IMAGE}

# Locen venv, da odvisnosti P4Runtime ne posegajo v mitmproxyjeve.
RUN python3 -m venv /opt/p4venv \
    && /opt/p4venv/bin/pip install --no-cache-dir p4runtime-shell pyyaml

COPY content_block.py /opt/proxy/content_block.py
COPY proxy_stats.py /opt/proxy/proxy_stats.py
COPY steer.py /opt/proxy/steer.py

CMD ["sleep", "infinity"]
