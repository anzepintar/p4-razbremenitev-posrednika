#!/usr/bin/env bash
#   ./start.sh <postavitev> [--content-block] [--web]
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

OUT=out
SUDO="${SUDO-sudo}"
MITM_CA=/data/mitmproxy/mitmproxy-ca-cert.pem
GRPC=10.20.1.2:9559
PROBE_URL="${PROBE_URL:-https://quic.anzepintar.com/}"
WEB_PASSWORD="${WEB_PASSWORD:-diploma}"

TOPO="${1:?uporaba: start.sh <postavitev> [--content-block] [--web]}"
TOPO_FILE=../$TOPO.clab.yml
shift
CONTENT_BLOCK=0
WEB=0
for arg in "$@"; do
	case "$arg" in
	--content-block) CONTENT_BLOCK=1 ;;
	--web) WEB=1 ;;
	*) echo "start.sh: neznana zastavica '$arg'" >&2; exit 2 ;;
	esac
done

case "$TOPO" in
A0) HAS_SWITCH=0 HAS_SERVER=1 ;;
A1) HAS_SWITCH=0 HAS_SERVER=0 ;;
B0) HAS_SWITCH=1 HAS_SERVER=1 ;;
B1) HAS_SWITCH=1 HAS_SERVER=0 ;;
*) echo "start.sh: neznana postavitev '$TOPO'" >&2; exit 2 ;;
esac

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
	clab deploy -t "$TOPO_FILE" --reconfigure >/dev/null
phase "postavljeno: $TOPO"

if [ "$HAS_SWITCH" = 1 ]; then
	docker exec -d "$(node switch)" sh -c \
		"exec /opt/switch/start_switch.sh >>/opt/traffic/out/switch.log 2>&1"
	wait_port switch 9559
	phase "switch running"

	docker exec "$(node mitm)" \
		/opt/p4venv/bin/python /opt/proxy/steer.py --grpc-addr "$GRPC" >>"$OUT/steer.log" 2>&1 || {
		echo "start.sh: seznamov ni bilo mogoce zapisati, glej $OUT/steer.log" >&2
		exit 1
	}
	phase "seznami zapisani v stikalo"
fi

if [ "$HAS_SERVER" = 1 ]; then
	clab exec -t "$TOPO_FILE" --label clab-node-name=server \
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
    print(site.domain, scenario.server_ip, site.label)
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
fi

ADDONS=(-s /opt/proxy/proxy_stats.py -s /opt/proxy/sni_block.py)
if [ "$CONTENT_BLOCK" = 1 ]; then
	ADDONS+=(-s /opt/proxy/content_block.py)
fi

# Beli seznam posrednik le tunelira, zato teh sej ne desifrira in jih ne vidi.
IGNORE=()
WHITE=$(python3 - <<'PY'
import sys

sys.path.insert(0, ".")
import sni

print(sni.ignore_hosts(sni.load("domain")["white"]))
PY
)
if [ -n "$WHITE" ]; then
	IGNORE=(--ignore-hosts "$WHITE")
	phase "beli seznam: $(printf '%s' "$WHITE" | tr '|' '\n' | wc -l) domen brez pregleda"
fi

# Navzgor preverjamo Caddyjev CA le v lab postavitvah; v splet gre s sistemsko zalogo.
UPSTREAM=()
if [ "$HAS_SERVER" = 1 ]; then
	UPSTREAM=(--set ssl_verify_upstream_trusted_ca=/opt/traffic/pki/trust.pem)
fi

TOOL=mitmdump
WEB_OPTS=()
if [ "$WEB" = 1 ]; then
	TOOL=mitmweb
	WEB_OPTS=(--web-host 0.0.0.0 --no-web-open-browser
		--set web_password="$WEB_PASSWORD")
fi

docker exec -d "$(node mitm)" sh -c 'exec "$@" >>/opt/traffic/out/mitm.log 2>&1' _ "$TOOL" \
	--mode transparent@8080 \
	--showhost \
	--set confdir=/data/mitmproxy \
	"${UPSTREAM[@]}" \
	"${IGNORE[@]}" \
	"${WEB_OPTS[@]}" \
	"${ADDONS[@]}"

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
wait_port mitm 8080
phase "proxy running"

if [ "$WEB" = 1 ]; then
	wait_port mitm 8081
	MITM_IP=$(docker inspect -f \
		'{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$(node mitm)")
	phase "web GUI: http://$MITM_IP:8081/?token=$WEB_PASSWORD"
fi

if [ "$HAS_SERVER" = 1 ]; then
	read -r PROBE_DOMAIN PROBE_IP _ <<<"$(awk '$3 == "ben" {print; exit}' "$OUT/warmup.txt")"
	PROBE=("--resolve" "$PROBE_DOMAIN:443:$PROBE_IP" "https://$PROBE_DOMAIN/index.html")
	TARGET="$PROBE_DOMAIN"
else
	# V splet gre kontrolna zahteva prek HTTP/3, torej hkrati preveri prestrezanje QUIC-a.
	PROBE=("--http3-only" "$PROBE_URL")
	TARGET="$PROBE_URL"
fi

for _ in $(seq 1 60); do
	code=$(docker exec "$(node client)" curl -s -o /dev/null -w '%{http_code}' \
		--max-time 5 --cacert /opt/traffic/pki/trust.pem "${PROBE[@]}" 2>/dev/null || true)
	[ "$code" = "200" ] && break
	sleep 1
done
[ "${code:-}" = "200" ] && phase "warmed up ($TARGET)" || {
	echo "start.sh: $TARGET ni dosegljiv (koda '${code:-}')" >&2
	exit 1
}
