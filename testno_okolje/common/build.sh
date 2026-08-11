#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

BMV2_VERSION="${BMV2_VERSION:-1.15.5}"
BMV2_IMAGE="bmv2-perf:$BMV2_VERSION"

python3 gen_caddyfile.py
python3 ids/gen_rules.py

docker build -t server:latest -f server/Dockerfile server
docker build -t client:latest -f client/Dockerfile client
docker build -t proxy:latest -f proxy/Dockerfile proxy

# Gradnja bmv2 iz izvorne kode traja 7 min, če uporabiš ze zgrajenega je hitreje
if [ -z "$(docker images -q "$BMV2_IMAGE")" ]; then
	docker build -t "$BMV2_IMAGE" \
		--build-arg BMV2_VERSION="$BMV2_VERSION" \
		-f switch/bmv2.Dockerfile switch
fi

docker build -t p4-switch:latest \
	--build-arg BMV2_IMAGE="$BMV2_IMAGE" \
	-f switch/Dockerfile switch

docker build -t p4-controller:latest -f controller/Dockerfile controller
docker build -t ids:latest -f ids/Dockerfile ids
