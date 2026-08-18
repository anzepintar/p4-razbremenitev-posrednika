#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

BMV2_VERSION="${BMV2_VERSION:-1.15.5}"
BMV2_IMAGE="bmv2-perf:$BMV2_VERSION"
MITM_SRC="${MITM_SRC:-../../mitmproxy-quic-transparent}"
MITM_IMAGE="${MITM_IMAGE:-mitmproxy-quic:latest}"

python3 gen_caddyfile.py

docker build -t server:latest -f server/Dockerfile server
docker build -t client:latest -f client/Dockerfile client

if [ -z "$(docker images -q browser:latest)" ]; then
	docker build -t browser:latest -f browser/Dockerfile browser
fi

if [ -z "$(docker images -q "$MITM_IMAGE")" ]; then
	[ -d "$MITM_SRC" ] || {
		echo "build.sh: forka mitmproxy ni v $MITM_SRC (nastavi MITM_SRC)" >&2
		exit 1
	}
	docker build -t "$MITM_IMAGE" -f proxy/mitmproxy.Dockerfile "$MITM_SRC"
fi

docker build -t proxy:latest \
	--build-arg MITM_IMAGE="$MITM_IMAGE" \
	-f proxy/Dockerfile proxy

if [ -z "$(docker images -q "$BMV2_IMAGE")" ]; then
	docker build -t "$BMV2_IMAGE" \
		--build-arg BMV2_VERSION="$BMV2_VERSION" \
		-f switch/bmv2.Dockerfile switch
fi

docker build -t p4-switch:latest \
	--build-arg BMV2_IMAGE="$BMV2_IMAGE" \
	-f switch/Dockerfile switch
