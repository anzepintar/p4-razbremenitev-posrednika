#!/usr/bin/env bash
#   ./trust.sh <postavitev>
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

TOPO="${1:?uporaba: trust.sh <postavitev>}"
TIMEOUT="${TIMEOUT:-60}"

SERVER="clab-${TOPO}-server"
PROXY="clab-${TOPO}-mitm"
CADDY_CA=/data/caddy/pki/authorities/local/root.crt
MITM_CA=/data/mitmproxy/mitmproxy-ca-cert.pem

mkdir -p pki
: >pki/trust.pem
sources=()

# Postavitvi *_internet streznika nimata, tam gre navzgor pravi splet.
if docker exec "$SERVER" true 2>/dev/null; then
	for _ in $(seq 1 "$TIMEOUT"); do
		docker exec "$SERVER" test -s "$CADDY_CA" 2>/dev/null && break
		sleep 1
	done

	if ! docker exec "$SERVER" test -s "$CADDY_CA" 2>/dev/null; then
		echo "Caddyjevega CA ni v $SERVER:$CADDY_CA - ali streznik ze tece?" >&2
		exit 1
	fi
	docker exec "$SERVER" cat "$CADDY_CA" >>pki/trust.pem
	sources+=(Caddy)
fi

# Ob prvem klicu posrednik se ne tece in svojega CA se nima.
if docker exec "$PROXY" test -s "$MITM_CA" 2>/dev/null; then
	docker exec "$PROXY" cat "$MITM_CA" >>pki/trust.pem
	sources+=(mitmproxy)
fi

echo "common/pki/trust.pem: ${sources[*]:-prazen}"
