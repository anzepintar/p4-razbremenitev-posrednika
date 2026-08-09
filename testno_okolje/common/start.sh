#!/usr/bin/env bash
#   ./start.sh <topologija> [--policy ime] [--content-block] [--no-deploy]
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

TOPO_DIR=..
OUT=out
SUDO="${SUDO-sudo}"
MITM_CA=/data/mitmproxy/mitmproxy-ca-cert.pem

TOPO="${1:?uporaba: start.sh <topologija> [--policy ime] [--content-block]}"
shift
POLICY=""
CONTENT_BLOCK=0
DEPLOY=1

while [ $# -gt 0 ]; do
	case "$1" in
	--policy) POLICY="$2"; shift 2 ;;
	--content-block) CONTENT_BLOCK=1; shift ;;
	--no-deploy) DEPLOY=0; shift ;;
	*) echo "start.sh: neznan argument '$1'" >&2; exit 2 ;;
	esac
done

case "$TOPO" in
client_server)      HAS_SWITCH=0 HAS_CTRL=0 HAS_MITM=0 HAS_IDS=0 ;;
mitm_baseline)      HAS_SWITCH=0 HAS_CTRL=0 HAS_MITM=1 HAS_IDS=0 ;;
mitm_controller)    HAS_SWITCH=0 HAS_CTRL=1 HAS_MITM=1 HAS_IDS=0 ;;
p4_baseline)        HAS_SWITCH=1 HAS_CTRL=0 HAS_MITM=0 HAS_IDS=0 ;;
p4_controller_mitm) HAS_SWITCH=1 HAS_CTRL=1 HAS_MITM=1 HAS_IDS=0 ;;
p4_controller_ids)  HAS_SWITCH=1 HAS_CTRL=1 HAS_MITM=0 HAS_IDS=1 ;;
p4_full)            HAS_SWITCH=1 HAS_CTRL=1 HAS_MITM=1 HAS_IDS=1 ;;
*) echo "start.sh: neznana topologija '$TOPO'" >&2; exit 2 ;;
esac

[ -n "$POLICY" ] || POLICY=$([ "$HAS_IDS" = 1 ] && { [ "$HAS_MITM" = 1 ] && echo full || echo ids; } || echo mitm)

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

if [ "$DEPLOY" = 1 ]; then
	$SUDO SWITCH_IMAGE="${SWITCH_IMAGE:-p4-switch:latest}" \
		clab deploy -t "$TOPO_DIR/$TOPO.clab.yml" --reconfigure >/dev/null
	phase "postavljeno: $TOPO"
fi

if [ "$HAS_SWITCH" = 1 ]; then
	docker exec -d "$(node switch)" sh -c \
		"exec env NO_PIPELINE=$HAS_CTRL /opt/switch/start_switch.sh >>/opt/traffic/out/switch.log 2>&1"
	wait_port switch 9559
	phase "stikalo tece"
fi

if [ "$HAS_CTRL" = 1 ]; then
	GRPC=()
	[ "$HAS_SWITCH" = 1 ] && GRPC=(--grpc-addr 10.20.1.2:9559)
	docker exec -d "$(node controller)" sh -c \
		"exec python3 /opt/traffic/controller/controller.py ${GRPC[*]-} --policy $POLICY \
		 >>/opt/traffic/out/controller.log 2>&1"
	# Vticnica posluša ze ob konstrukciji streznika, zato preverimo pravi odgovor.
	for _ in $(seq 1 60); do
		docker exec "$(node controller)" python3 -c \
			"import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/state', timeout=2)" \
			>/dev/null 2>&1 && break
		sleep 1
	done
	docker exec "$(node controller)" python3 -c \
		"import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/state', timeout=2)" \
		>/dev/null 2>&1 || {
		echo "start.sh: krmilnik ne odgovarja, glej out/controller.log" >&2
		tail -20 "$OUT/controller.log" >&2 || true
		exit 1
	}
	phase "krmilnik tece, politika '$POLICY'"
fi

clab exec -t "$TOPO_DIR/$TOPO.clab.yml" --label clab-node-name=server \
	--cmd "caddy start --config /opt/traffic/server/Caddyfile" >/dev/null 2>&1
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

warmed=$(docker exec "$(node server)" sh -c '
	served=0
	while read -r domain ip _; do
		code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 \
			--resolve "$domain:443:$ip" "https://$domain/index.html" 2>/dev/null || true)
		[ "$code" = "200" ] && served=$((served + 1))
	done </opt/traffic/out/warmup.txt
	echo "$served"')
phase "streznik tece, certifikati izdani za $warmed od $(wc -l <"$OUT/warmup.txt") domen"

if [ "$HAS_MITM" = 1 ]; then
	# proxy_stats je vedno naložen, da so postavitve s posrednikom med seboj primerljive.
	ADDONS=(-s /opt/proxy/sni_passthrough.py -s /opt/proxy/proxy_stats.py)
	[ "$HAS_CTRL" = 1 ] && [ "$HAS_SWITCH" = 0 ] && ADDONS+=(-s /opt/proxy/controller_bypass.py)
	[ "$CONTENT_BLOCK" = 1 ] && ADDONS+=(-s /opt/proxy/content_block.py)

	docker exec -d "$(node mitm)" sh -c 'exec mitmdump "$@" >>/opt/traffic/out/mitm.log 2>&1' _ \
		--set confdir=/data/mitmproxy \
		--set ssl_verify_upstream_trusted_ca=/opt/traffic/pki/trust.pem \
		--set keep_host_header=true \
		"${ADDONS[@]}" \
		--mode reverse:https://10.0.2.10:443@8443 \
		--mode reverse:https://10.0.2.11:443@8444 \
		--mode reverse:https://10.0.2.12:443@8445

	# Pravili brez akcije samo steteta promet odjemalcev: kar je prestrezeno, gre v
	# INPUT (po REDIRECT), kar je prepusceno, pa v FORWARD. Stevci vmesnika za to
	# niso uporabni, ker ima posrednik pri P4 en sam vmesnik za obe smeri.
	docker exec "$(node mitm)" sh -c '
		iptables -D INPUT -s 10.0.1.0/24 2>/dev/null
		iptables -D FORWARD -s 10.0.1.0/24 2>/dev/null
		iptables -I INPUT 1 -s 10.0.1.0/24
		iptables -I FORWARD 1 -s 10.0.1.0/24' || true

	# trust.sh pobere le ze obstojece CA, zato pocakamo na mitmproxyjevega.
	for _ in $(seq 1 60); do
		docker exec "$(node mitm)" test -s "$MITM_CA" 2>/dev/null && break
		sleep 1
	done
	./trust.sh "$TOPO" >/dev/null
	wait_port mitm 8443
	phase "posrednik tece"
fi

if [ "$HAS_IDS" = 1 ]; then
	docker exec -d "$(node ids)" sh -c 'exec /opt/ids/start_ids.sh >>/opt/traffic/out/ids.log 2>&1'
	for _ in $(seq 1 60); do
		[ -s "$OUT/eve.json" ] && break
		sleep 1
	done
	[ -s "$OUT/eve.json" ] || {
		echo "start.sh: Suricata se ni zagnala, glej out/ids.log" >&2
		exit 1
	}
	docker exec -d "$(node ids)" sh -c \
		'exec python3 /opt/ids/alert_forward.py >>/opt/traffic/out/forward.log 2>&1'
	phase "IDS tece"
fi

# Celotna pot mora sluziti, preden runner zacne meriti. Sonda gre na legitimno
# domeno, da ne sprozi IDS in ne zniza zaupanja se pred meritvijo.
read -r PROBE_DOMAIN PROBE_IP _ <<<"$(awk '$3 == "ben" {print; exit}' "$OUT/warmup.txt")"
for _ in $(seq 1 60); do
	code=$(docker exec "$(node client)" curl -s -o /dev/null -w '%{http_code}' \
		--max-time 5 --cacert /opt/traffic/pki/trust.pem \
		--resolve "$PROBE_DOMAIN:443:$PROBE_IP" "https://$PROBE_DOMAIN/index.html" 2>/dev/null || true)
	[ "$code" = "200" ] && break
	sleep 1
done
[ "${code:-}" = "200" ] && phase "pot je ogreta ($PROBE_DOMAIN)" || {
	echo "start.sh: $PROBE_DOMAIN ni dosegljiv (koda '${code:-}')" >&2
	exit 1
}
