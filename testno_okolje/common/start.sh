#!/usr/bin/env bash
#   ./start.sh <postavitev> [--content-block]
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

TOPO_DIR=..
OUT=out
SUDO="${SUDO-sudo}"
MITM_CA=/data/mitmproxy/mitmproxy-ca-cert.pem

TOPO="${1:?uporaba: start.sh <postavitev> [--content-block]}"
CONTENT_BLOCK=0
if [ "${2:-}" = "--content-block" ]; then
	CONTENT_BLOCK=1
fi

case "$TOPO" in
client_server)      HAS_SWITCH=0 HAS_CTRL=0 HAS_MITM=0 HAS_IDS=0 ;;
mitm_baseline)      HAS_SWITCH=0 HAS_CTRL=0 HAS_MITM=1 HAS_IDS=0 ;;
mitm_controller)    HAS_SWITCH=0 HAS_CTRL=1 HAS_MITM=1 HAS_IDS=0 ;;
p4_baseline)        HAS_SWITCH=1 HAS_CTRL=0 HAS_MITM=0 HAS_IDS=0 ;;
p4_controller_mitm) HAS_SWITCH=1 HAS_CTRL=1 HAS_MITM=1 HAS_IDS=0 ;;
p4_controller_ids)  HAS_SWITCH=1 HAS_CTRL=1 HAS_MITM=0 HAS_IDS=1 ;;
p4_full)            HAS_SWITCH=1 HAS_CTRL=1 HAS_MITM=1 HAS_IDS=1 ;;
*) echo "start.sh: neznana postavitev '$TOPO'" >&2; exit 2 ;;
esac

POLICY=$([ "$HAS_IDS" = 1 ] && { [ "$HAS_MITM" = 1 ] && echo full || echo ids; } || echo mitm)

node() { echo "clab-$TOPO-$1"; }

PHASE=$(date +%s)
phase() {
	local now
	now=$(date +%s)
	printf '%-52s %3ss\n' "$1" "$((now - PHASE))"
	PHASE=$now
}

wait_port() {
	local name port
	name=$(node "$1")
	port="$2"
	for _ in $(seq 1 60); do
		docker exec "$name" ss -lntu 2>/dev/null | grep -q ":$port" && return 0
		sleep 1
	done
	echo "start.sh: $name ne poslusa na $port" >&2
	return 1
}

mkdir -p "$OUT"

$SUDO env CLIENT_CPU="${CLIENT_CPU:-2}" \
	clab deploy -t "$TOPO_DIR/$TOPO.clab.yml" --reconfigure >/dev/null
phase "postavljeno: $TOPO"

if [ "$HAS_SWITCH" = 1 ]; then
	docker exec -d "$(node switch)" sh -c \
		"exec env NO_PIPELINE=$HAS_CTRL /opt/switch/start_switch.sh >>/opt/traffic/out/switch.log 2>&1"
	wait_port switch 9559
	phase "switch running"
fi

if [ "$HAS_CTRL" = 1 ]; then
	GRPC=""
	if [ "$HAS_SWITCH" = 1 ]; then GRPC="--grpc-addr 10.20.1.2:9559"; fi
	docker exec -d "$(node controller)" sh -c \
		"exec python3 /opt/traffic/controller/controller.py $GRPC --policy $POLICY \
		 >>/opt/traffic/out/controller.log 2>&1"

	for _ in $(seq 2 60); do
		docker exec "$(node controller)" python3 -c \
			"import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/state', timeout=2)" \
			>/dev/null 2>&1 && break
		sleep 1
	done
	docker exec "$(node controller)" python3 -c \
		"import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/state', timeout=2)" \
		>/dev/null 2>&1 || {
		echo "start.sh: krmilnik ne odgovarja, glej $OUT/controller.log" >&2
		exit 1
	}
	phase "controller running, policy '$POLICY'"
fi

clab exec -t "$TOPO_DIR/$TOPO.clab.yml" --label clab-node-name=server \
	--cmd "caddy start --config /opt/traffic/server/Caddyfile" >>"$OUT/caddy.log" 2>&1 || {
	echo "start.sh: caddy se ni zagnal, glej $OUT/caddy.log" >&2
	exit 1
}
./trust.sh "$TOPO" >/dev/null

python3 - >"$OUT/warmup.txt" <<'PY'
import sys
from pathlib import Path

sys.path.insert(0, str(Path("client").resolve()))
from runner import scenario as scenario_mod

scenario = scenario_mod.load("scenario.yml", testset="server/testset")
for site in sorted(scenario.sites.values(), key=lambda s: s.domain):
    print(site.domain, site.ip, site.label)
PY

warmed=$(timeout "${WARMUP_TIMEOUT:-600}" docker exec "$(node server)" sh -c '
	xargs -P '"${WARMUP_JOBS:-16}"' -n 3 sh -c '\''
		code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 \
			--resolve "$1:443:$2" "https://$1/index.html" 2>/dev/null || true)
		[ "$code" = "200" ] && echo .
	'\'' _ </opt/traffic/out/warmup.txt | wc -l') || true
warmed=$(printf '%s' "${warmed:-0}" | tr -dc '0-9')
warmed="${warmed:-0}"
total=$(wc -l <"$OUT/warmup.txt")
phase "server running, certifikati izdani za $warmed od $total domen"
if [ "$warmed" -lt "$total" ]; then
	echo "start.sh: ogretih le $warmed od $total domen - meritev bo videla napake TLS" >&2
fi

if [ "$HAS_MITM" = 1 ]; then
	ADDONS=(-s /opt/proxy/sni_passthrough.py -s /opt/proxy/proxy_stats.py)
	if [ "$HAS_CTRL" = 1 ] && [ "$HAS_SWITCH" = 0 ]; then
		ADDONS+=(-s /opt/proxy/controller_bypass.py)
	fi
	if [ "$CONTENT_BLOCK" = 1 ]; then
		ADDONS+=(-s /opt/proxy/content_block.py)
	fi

	docker exec -d "$(node mitm)" sh -c 'exec mitmdump "$@" >>/opt/traffic/out/mitm.log 2>&1' _ \
		--set confdir=/data/mitmproxy \
		--set ssl_verify_upstream_trusted_ca=/opt/traffic/pki/trust.pem \
		--set keep_host_header=true \
		"${ADDONS[@]}" \
		--mode reverse:https://10.0.2.10:443@8443 \
		--mode reverse:https://10.0.2.11:443@8444 \
		--mode reverse:https://10.0.2.12:443@8445

	docker exec "$(node mitm)" sh -c '
		iptables -D INPUT -s 10.0.1.0/24 2>/dev/null
		iptables -D FORWARD -s 10.0.1.0/24 2>/dev/null
		iptables -I INPUT 1 -s 10.0.1.0/24
		iptables -I FORWARD 1 -s 10.0.1.0/24' || true

	for _ in $(seq 1 60); do
		docker exec "$(node mitm)" test -s "$MITM_CA" 2>/dev/null && break
		sleep 1
	done
	./trust.sh "$TOPO" >/dev/null
	wait_port mitm 8443
	phase "proxy running"
fi

if [ "$HAS_IDS" = 1 ]; then
	docker exec -d "$(node ids)" sh -c 'exec /opt/ids/start_ids.sh >>/opt/traffic/out/ids.log 2>&1'
	for _ in $(seq 1 60); do
		[ -s "$OUT/eve.json" ] && break
		sleep 1
	done
	[ -s "$OUT/eve.json" ] || {
		echo "start.sh: Suricata se ni zagnala, glej $OUT/ids.log" >&2
		exit 1
	}
	docker exec -d "$(node ids)" sh -c \
		'exec python3 /opt/ids/alert_forward.py >>/opt/traffic/out/ids.log 2>&1'
	phase "IDS running"
fi

read -r PROBE_DOMAIN PROBE_IP _ <<<"$(awk '$3 == "ben" {print; exit}' "$OUT/warmup.txt")"
for _ in $(seq 1 60); do
	code=$(docker exec "$(node client)" curl -s -o /dev/null -w '%{http_code}' \
		--max-time 5 --cacert /opt/traffic/pki/trust.pem \
		--resolve "$PROBE_DOMAIN:443:$PROBE_IP" "https://$PROBE_DOMAIN/index.html" 2>/dev/null || true)
	[ "$code" = "200" ] && break
	sleep 1
done
[ "${code:-}" = "200" ] && phase "warmed up ($PROBE_DOMAIN)" || {
	echo "start.sh: $PROBE_DOMAIN ni dosegljiv (koda '${code:-}')" >&2
	exit 1
}
