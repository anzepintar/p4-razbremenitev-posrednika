#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

if [ ! -d server/testset ]; then
	echo "najprej poženi ./build_testset.py" >&2
	exit 1
fi

python3 gen_caddyfile.py

docker build -t server:latest -f server/Dockerfile server

docker build -t client:latest -f client/Dockerfile client

docker build -t proxy:latest -f proxy/Dockerfile proxy

docker build -t tests:latest -f tests/Dockerfile .