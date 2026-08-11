# Gradnja bmv2 iz izvorne kode z optimizacijskimi zastavicami.

ARG PI_IMAGE=p4lang/pi:latest
FROM ${PI_IMAGE}

ARG BMV2_VERSION=1.15.5
ARG BMV2_OPT="-g -O3"

ENV BM_DEPS="build-essential ca-certificates cmake curl git libgmp-dev libpcap-dev \
             libboost-dev libboost-program-options-dev libboost-system-dev \
             libboost-filesystem-dev libboost-thread-dev libjsoncpp-dev \
             libxxhash-dev pkg-config"
ENV BM_RUNTIME_DEPS="libboost-program-options1.83.0 libboost-system1.83.0 \
                     libboost-filesystem1.83.0 libboost-thread1.83.0 \
                     libgmp10 libpcap0.8t64 libxxhash0 python3 python3-six \
                     python-is-python3"

RUN apt-get update -qq \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tzdata \
    && apt-get install -qq --no-install-recommends $BM_DEPS $BM_RUNTIME_DEPS \
    && git clone --depth 1 --branch "$BMV2_VERSION" \
         https://github.com/p4lang/behavioral-model.git /bmv2 \
    && cmake -S /bmv2 -B /bmv2/build \
         -DCMAKE_BUILD_TYPE=Release \
         -DCMAKE_CXX_FLAGS_RELEASE="$BMV2_OPT -DNDEBUG" \
         -DCMAKE_C_FLAGS_RELEASE="$BMV2_OPT -DNDEBUG" \
         -DENABLE_LOGGING_MACROS=OFF \
         -DENABLE_ELOGGER=OFF \
         -DENABLE_DEBUGGER=OFF \
         -DWITH_PI=ON \
         -DWITH_THRIFT=ON \
         -DWITH_TARGETS=ON \
         -DWITH_NANOMSG=ON \
         -DWITH_PDFIXED=OFF \
         -DWITH_STRESS_TESTS=OFF \
         -DENABLE_WERROR=OFF \
    && cmake --build /bmv2/build -j"$(nproc)" \
    && cmake --install /bmv2/build \
    && ldconfig \
    && rm -rf /bmv2 /var/cache/apt/* /var/lib/apt/lists/*
