#!/usr/bin/env bash
#
#   ./capture.sh <topologija> [vozel] [vmesnik]
#   ./capture.sh client_server client
#   ./capture.sh --stop <topologija> [vozel]
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

STOP=0
if [ "${1:-}" = "--stop" ]; then
	STOP=1
	shift
fi

TOPO="${1:?uporaba: capture.sh <topologija> [vozel] [vmesnik]}"
NODE="${2:-client}"
IFACE="${3:-eth1}"
CONTAINER="clab-${TOPO}-${NODE}"
PCAP="/opt/traffic/out/${TOPO}-${NODE}.pcap"

if [ "$STOP" -eq 1 ]; then
	docker exec "$CONTAINER" pkill -INT tcpdump || true
	echo "zajem ustavljen: out/${TOPO}-${NODE}.pcap"
	exit 0
fi

mkdir -p out
docker exec -d "$CONTAINER" tcpdump -i "$IFACE" -w "$PCAP" -U 'tcp port 443 or udp port 443'
echo "zajem tece v $CONTAINER -> out/${TOPO}-${NODE}.pcap"
echo
echo "Za desifriranje v Wiresharku nastavi orkestratorju SSLKEYLOGFILE:"
echo "  SSLKEYLOGFILE=/opt/traffic/out/keys.log python3 -m runner --config /opt/traffic/scenario.yml"
echo "nato v Wiresharku: Preferences -> Protocols -> TLS -> (Pre)-Master-Secret log filename"
echo "  -> out/keys.log   (desifrira HTTP/2 in HTTP/3 iz iste datoteke)"
