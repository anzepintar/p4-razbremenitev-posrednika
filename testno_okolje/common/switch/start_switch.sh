#!/usr/bin/env bash
set -euo pipefail

BUILD=/opt/switch/build
SHARED=/opt/traffic/switch/build
PORTS=()

# Vrata so fiksna: 1 klient, 2 streznik, 3 mitm, 4 ids.
for port in 1 2 3 4; do
	iface="eth$port"
	[ -e "/sys/class/net/$iface" ] || continue

	ip link set dev "$iface" up
	ip link set dev "$iface" promisc on
	ethtool -K "$iface" rx off tx off sg off tso off gso off gro off lro off >/dev/null 2>&1 || true

	PORTS+=(-i "$port@$iface")
done

if [ "${#PORTS[@]}" -eq 0 ]; then
	echo "start_switch: nobenega vmesnika eth1-eth4 - ali je topologija postavljena?" >&2
	exit 1
fi

mkdir -p "$SHARED"
cp "$BUILD"/steering.json "$BUILD"/steering.p4info.txtpb "$SHARED"/

LOG=()
if [ "${SWITCH_LOG:-0}" = "1" ]; then
	LOG=(--log-console)
fi

PIPELINE=("$BUILD/steering.json")
if [ "${NO_PIPELINE:-0}" = "1" ]; then
	PIPELINE=(--no-p4)
fi

echo "start_switch: ${PORTS[*]} ${PIPELINE[*]}"
exec simple_switch_grpc --device-id 0 "${PORTS[@]}" "${LOG[@]}" \
	"${PIPELINE[@]}" \
	-- --grpc-server-addr 0.0.0.0:9559
