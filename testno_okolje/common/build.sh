#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

python3 gen_caddyfile.py

python3 ids/gen_rules.py

docker build -t server:latest -f server/Dockerfile server

docker build -t client:latest -f client/Dockerfile client

docker build -t proxy:latest -f proxy/Dockerfile proxy

BMV2_VERSION="${BMV2_VERSION:-1.15.5}"
BMV2_PROFILE="${BMV2_PROFILE:-perf}"
BMV2_IMAGE="bmv2-${BMV2_PROFILE}:${BMV2_VERSION}"
SWITCH_TAG="latest"
if [ "$BMV2_PROFILE" = "debug" ]; then
	SWITCH_TAG="debug"
fi

if [ -z "$(docker images -q "$BMV2_IMAGE")" ] || [ "${BMV2_REBUILD:-0}" = "1" ]; then
	echo "build.sh: gradim $BMV2_IMAGE (traja ~15-30 min)"
	docker build -t "$BMV2_IMAGE" \
		--build-arg BMV2_VERSION="$BMV2_VERSION" \
		--build-arg BMV2_PROFILE="$BMV2_PROFILE" \
		-f switch/bmv2.Dockerfile switch
fi

docker build -t "p4-switch:$SWITCH_TAG" \
	--build-arg BMV2_IMAGE="$BMV2_IMAGE" \
	-f switch/Dockerfile switch

docker build -t p4-controller:latest -f controller/Dockerfile controller

docker build -t ids:latest -f ids/Dockerfile ids