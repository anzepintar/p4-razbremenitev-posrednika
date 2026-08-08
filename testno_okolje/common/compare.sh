#!/usr/bin/env bash
#   ./compare.sh [stevilo_zahtev_na_odjemalca]
#   A brez posrednika, B posrednik brez pregleda, C posrednik s pregledom vsebine.
#   Rezultati gredo v out/{A,B,C}/, povzetek naredi compare.py.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

REQUESTS="${1:-40}"
TOPO_DIR=..
OUT=out
SUDO="${SUDO-sudo}"
CURRENT=""

MITM_CA=/data/mitmproxy/mitmproxy-ca-cert.pem

cleanup() {
	if [ -n "$CURRENT" ]; then
		$SUDO clab destroy -t "$TOPO_DIR/$CURRENT.clab.yml" --cleanup >/dev/null || true
		CURRENT=""
	fi
}
trap cleanup EXIT

deploy() {
	CURRENT="$1"
	$SUDO clab deploy -t "$TOPO_DIR/$1.clab.yml" --reconfigure
	clab exec -t "$TOPO_DIR/$1.clab.yml" --label clab-node-name=server \
		--cmd "caddy start --config /opt/traffic/server/Caddyfile"
	./trust.sh "$1"
}

start_mitm() {
	local topo="$1" log="$2"
	shift 2
	# Izhod detached execa se zavrze, zato mitmdump pisemo v out/, sicer okvare niso vidne.
	docker exec -d "clab-$topo-mitm" sh -c 'exec mitmdump "$@" >>"$0" 2>&1' \
		"/opt/traffic/out/$log" \
		--set confdir=/data/mitmproxy \
		--set ssl_verify_upstream_trusted_ca=/opt/traffic/pki/trust.pem \
		--set keep_host_header=true \
		-s /opt/proxy/sni_passthrough.py \
		"$@" \
		--mode reverse:https://10.0.2.10:443@8443 \
		--mode reverse:https://10.0.2.11:443@8444 \
		--mode reverse:https://10.0.2.12:443@8445

	# trust.sh pobere le ze obstojece CA, zato pocakamo na mitmproxyjevega.
	for _ in $(seq 1 60); do
		docker exec "clab-$topo-mitm" test -s "$MITM_CA" 2>/dev/null && break
		sleep 1
	done
	./trust.sh "$topo"

	for _ in $(seq 1 30); do
		docker exec "clab-$topo-mitm" ss -lntu 2>/dev/null | grep -q ':8443' && break
		sleep 1
	done
}

run() {
	local name="$1" topo="$2"
	rm -f "$OUT/metrics.jsonl" "$OUT/summary.json" "$OUT/verdicts.jsonl"

	clab exec -t "$TOPO_DIR/$topo.clab.yml" --label clab-node-name=client \
		--cmd "python3 -m runner --config /opt/traffic/scenario.yml --requests $REQUESTS"

	mkdir -p "$OUT/$name"
	for file in metrics.jsonl summary.json verdicts.jsonl; do
		if [ -f "$OUT/$file" ]; then
			mv "$OUT/$file" "$OUT/$name/$file"
		fi
	done
	echo "zagon $name -> $OUT/$name/"
}

echo "== A: brez posrednika =="
deploy client_server
run A client_server
cleanup

echo "== B: posrednik brez pregleda vsebine =="
deploy mitm_baseline
start_mitm mitm_baseline mitm-B.log
run B mitm_baseline
cleanup

echo "== C: posrednik s pregledom vsebine =="
deploy mitm_baseline
start_mitm mitm_baseline mitm-C.log -s /opt/proxy/content_block.py
run C mitm_baseline
cleanup

./compare.py --out "$OUT"
