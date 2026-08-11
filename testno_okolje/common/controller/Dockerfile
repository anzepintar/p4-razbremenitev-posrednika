FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir p4runtime-shell pyyaml

COPY controller.py /opt/controller/controller.py

CMD ["sleep", "infinity"]
