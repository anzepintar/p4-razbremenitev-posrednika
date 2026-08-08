#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

python3 gen_caddyfile.py

python3 ids/gen_rules.py

docker build -t server:latest -f server/Dockerfile server

docker build -t client:latest -f client/Dockerfile client

docker build -t proxy:latest -f proxy/Dockerfile proxy

docker build -t p4-switch:latest -f switch/Dockerfile switch

docker build -t p4-controller:latest -f controller/Dockerfile controller

docker build -t ids:latest -f ids/Dockerfile ids