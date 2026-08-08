FROM p4lang/p4c:1.2.5.16 AS build

COPY steering.p4 /src/steering.p4

# Preverjanje za napake v .p4
RUN mkdir -p /out && p4c --target bmv2 --arch v1model \
        --p4runtime-files /out/steering.p4info.txtpb \
        -o /out /src/steering.p4

FROM p4lang/behavioral-model:latest

RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 ethtool tcpdump iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out /opt/switch/build
COPY start_switch.sh /opt/switch/start_switch.sh

ENTRYPOINT []

CMD ["sleep", "infinity"]
