ARG BMV2_IMAGE=bmv2-perf:1.15.5-modules

FROM p4lang/p4c:1.2.5.16 AS p4build

COPY steering.p4 /src/steering.p4

RUN mkdir -p /out && p4c-bm2-ss --arch v1model --emit-externs \
        --p4runtime-files /out/steering.p4info.txtpb \
        -o /out/steering.json /src/steering.p4

FROM ${BMV2_IMAGE} AS externbuild

COPY quic_sni.h quic_sni.cpp quic_extern.cpp quic_selftest.cpp /src/

RUN mkdir -p /out && cd /src \
    && g++ -std=c++17 -Wall -Wextra -O2 -fPIC -shared \
        -o /out/quic_sni.so quic_sni.cpp quic_extern.cpp -lcrypto \
    && g++ -std=c++17 -Wall -Wextra -O2 \
        -o /out/quic_selftest quic_sni.cpp quic_selftest.cpp -lcrypto

FROM ${BMV2_IMAGE}

RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 ethtool \
    && rm -rf /var/lib/apt/lists/*

COPY --from=p4build /out /opt/switch/build
COPY --from=externbuild /out /opt/switch/lib
COPY start_switch.sh /opt/switch/start_switch.sh

ENTRYPOINT []

CMD ["sleep", "infinity"]
