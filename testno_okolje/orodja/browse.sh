#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

TOPO="${1:?uporaba: browse.sh B1 [chromium|firefox] [url]}"
BROWSER="${2:-chromium}"
URL="${3:-${PROBE_URL:-https://quic.anzepintar.com/}}"

case "$TOPO" in
B1) ;;
*) echo "browse.sh: brskalnik je le v B1, ne v '$TOPO'" >&2; exit 2 ;;
esac

NODE="clab-$TOPO-client"
WEB_PORT="${VNC_WEB_PORT:-6080}"
docker exec "$NODE" true 2>/dev/null || {
	echo "browse.sh: $NODE ne tece; pozeni ./orodja/start.sh $TOPO" >&2
	exit 1
}

if ! docker exec "$NODE" ss -lnt 2>/dev/null | grep -q ":$WEB_PORT"; then
	docker exec -d \
		-e VNC_PASSWORD="${VNC_PASSWORD:-diploma}" \
		-e VNC_GEOMETRY="${VNC_GEOMETRY:-1600x900x24}" \
		-e VNC_WEB_PORT="$WEB_PORT" \
		"$NODE" sh -c 'exec /opt/traffic/browser/vnc.sh >>/opt/traffic/out/vnc.log 2>&1'
	for _ in $(seq 1 60); do
		docker exec "$NODE" ss -lnt 2>/dev/null | grep -q ":$WEB_PORT" && break
		sleep 1
	done
	docker exec "$NODE" ss -lnt 2>/dev/null | grep -q ":$WEB_PORT" || {
		echo "browse.sh: novnc se ni zagnal, glej okolje/out/vnc.log" >&2
		exit 1
	}
fi

docker exec "$NODE" /opt/traffic/browser/trust_nss.sh >/dev/null

QUIC=""
case "${FORCE_QUIC:-}" in
"" | 0) ;;
1)
	QUIC=${URL#*://}
	QUIC=${QUIC%%/*}
	QUIC=${QUIC%%:*}
	;;
*) QUIC=$FORCE_QUIC ;;
esac

case "$BROWSER" in
chromium | firefox)
	docker exec -d -e DISPLAY=":99" -e FORCE_QUIC="$QUIC" "$NODE" \
		"diploma-$BROWSER" "$URL"
	;;
*)
	echo "browse.sh: neznan brskalnik '$BROWSER' (chromium ali firefox)" >&2
	exit 2
	;;
esac

NODE_IP=$(docker inspect -f \
	'{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$NODE")
echo "$BROWSER v $NODE: $URL${QUIC:+ (h3 vsiljen za $QUIC)}"
echo "namizje: http://$NODE_IP:$WEB_PORT/vnc.html (geslo ${VNC_PASSWORD:-diploma})"
