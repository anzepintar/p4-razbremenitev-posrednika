#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

OUT=out
SUDO="${SUDO-sudo}"
MITM_CA=/data/mitmproxy/mitmproxy-ca-cert.pem
GRPC=10.20.1.2:9559
PROBE_URL="${PROBE_URL:-https://quic.anzepintar.com/}"
WEB_PASSWORD="${WEB_PASSWORD:-diploma}"
VNC_PASSWORD="${VNC_PASSWORD:-diploma}"
VNC_GEOMETRY="${VNC_GEOMETRY:-1600x900x24}"
VNC_WEB_PORT="${VNC_WEB_PORT:-6080}"

TOPO="${1:?uporaba: start.sh <postavitev> [--content-block] [--web] [--lazy]}"
TOPO_FILE=../$TOPO.clab.yml
shift
CONTENT_BLOCK=0
WEB=0
LAZY=0
for arg in "$@"; do
	case "$arg" in
	--content-block) CONTENT_BLOCK=1 ;;
	--web) WEB=1 ;;
	--lazy) LAZY=1 ;;
	*) echo "start.sh: neznana zastavica '$arg'" >&2; exit 2 ;;
	esac
done

case "$TOPO" in
A0) HAS_SWITCH=0 HAS_SERVER=1 HAS_BROWSER=0 ;;
A1) HAS_SWITCH=0 HAS_SERVER=0 HAS_BROWSER=1 ;;
B0) HAS_SWITCH=1 HAS_SERVER=1 HAS_BROWSER=0 ;;
B1) HAS_SWITCH=1 HAS_SERVER=0 HAS_BROWSER=1 ;;
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
		/opt/p4venv/bin/python /opt/traffic/proxy/steer.py --grpc-addr "$GRPC" >>"$OUT/steer.log" 2>&1 || {
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

sys.path.insert(0, ".")
sys.path.insert(0, str(Path("client").resolve()))
from runner import scenario as scenario_mod

scenario = scenario_mod.load("experiment.yml", testset="server/testset")
for site in sorted(scenario.sites.values(), key=lambda s: s.domain):
    print(site.domain, site.ip, site.group)
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

ADDONS=(-s /opt/traffic/proxy/proxy_stats.py)
if [ "$CONTENT_BLOCK" = 1 ]; then
	docker exec "$(node mitm)" python3 /opt/traffic/proxy/content_block.py \
		>"$OUT/content_rules.log" 2>&1 || {
		echo "start.sh: vsebinskih pravil ni bilo mogoce prebrati:" >&2
		cat "$OUT/content_rules.log" >&2
		exit 1
	}
	ADDONS+=(-s /opt/traffic/proxy/content_block.py)
	phase "$(head -1 "$OUT/content_rules.log")"
fi

IGNORE=()
BLOCK=()
read -r WHITE BLACK <<<"$(python3 - <<'PY'
import sys

sys.path.insert(0, ".")
import sni

domains, ips = sni.load("domain"), sni.load("ip")
print(sni.ignore_hosts(domains["white"], ips["white"]) or "-",
      sni.block_filter(domains["black"], ips["black"]) or "-")
PY
)"

if [ "$WHITE" != "-" ]; then
	IGNORE=(--ignore-hosts "$WHITE")
	phase "beli seznam: $(printf '%s\n' "$WHITE" | tr '|' '\n' | wc -l) postavk brez pregleda"
fi
if [ "$BLACK" != "-" ]; then
	BLOCK=(--set "block_list=#~d \"$BLACK\"#444")
	phase "crni seznam: $(printf '%s\n' "$BLACK" | tr '|' '\n' | wc -l) postavk se zavrne"
fi

UPSTREAM=()
if [ "$HAS_SERVER" = 1 ]; then
	UPSTREAM=(--set ssl_verify_upstream_trusted_ca=/opt/traffic/pki/trust.pem)
fi

STRATEGY=()
if [ "$LAZY" = 1 ]; then
	STRATEGY=(--set connection_strategy=lazy)
	phase "connection_strategy=lazy"
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
	"${BLOCK[@]}" \
	"${STRATEGY[@]}" \
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

if [ "$HAS_BROWSER" = 1 ]; then
	docker exec "$(node client)" /opt/traffic/browser/trust_nss.sh \
		>>"$OUT/browser.log" 2>&1 || {
		echo "start.sh: CA ni bilo mogoce zaupati v odjemalcu, glej $OUT/browser.log" >&2
		exit 1
	}
	phase "CA zaupan v odjemalcu (sistem + NSS)"

	docker exec -d \
		-e VNC_PASSWORD="$VNC_PASSWORD" \
		-e VNC_GEOMETRY="$VNC_GEOMETRY" \
		-e VNC_WEB_PORT="$VNC_WEB_PORT" \
		"$(node client)" sh -c 'exec /opt/traffic/browser/vnc.sh >>/opt/traffic/out/vnc.log 2>&1'
	wait_port client "$VNC_WEB_PORT"
	CLIENT_IP=$(docker inspect -f \
		'{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$(node client)")
	phase "namizje: http://$CLIENT_IP:$VNC_WEB_PORT/vnc.html (geslo $VNC_PASSWORD)"
fi

if [ "$WEB" = 1 ]; then
	wait_port mitm 8081
	MITM_IP=$(docker inspect -f \
		'{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$(node mitm)")
	phase "web GUI: http://$MITM_IP:8081/?token=$WEB_PASSWORD"
fi

if [ "$HAS_SERVER" = 1 ]; then
	read -r PROBE_DOMAIN PROBE_IP _ <<<"$(awk '
		$3 == "unknown" { print; found = 1; exit }
		$3 == "sni_white" || $3 == "ip_white" { if (!fallback) fallback = $0 }
		END { if (!found && fallback) print fallback }
	' "$OUT/warmup.txt")"
	if [ -z "${PROBE_DOMAIN:-}" ]; then
		echo "start.sh: v razdelitvi ni domene iz skupine unknown, sni_white ali ip_white," >&2
		echo "  zato kontrolna zahteva ne more vrniti 200; popravi experiment.yml" >&2
		echo "  in pozeni ./common/gen_lists.py" >&2
		exit 1
	fi
	PROBE=("--resolve" "$PROBE_DOMAIN:443:$PROBE_IP" "https://$PROBE_DOMAIN/index.html")
	TARGET="$PROBE_DOMAIN"
else
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

if [ "$HAS_BROWSER" = 1 ]; then
	phase "brskalnik: ./common/browse.sh $TOPO [chromium|firefox] <url>"
fi
