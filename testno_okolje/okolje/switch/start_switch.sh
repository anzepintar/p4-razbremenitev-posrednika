#!/usr/bin/env bash
set -euo pipefail

BUILD=/opt/switch/build
SHARED=/opt/traffic/switch/build
MODULE=/opt/switch/lib/quic_sni.so
PORTS=()

for port in 1 2 3; do
	iface="eth$port"
	[ -e "/sys/class/net/$iface" ] || continue

	ip link set dev "$iface" up
	ip link set dev "$iface" promisc on
	ethtool -K "$iface" rx off tx off sg off tso off gso off gro off lro off >/dev/null 2>&1 || true

	PORTS+=(-i "$port@$iface")
done

if [ "${#PORTS[@]}" -eq 0 ]; then
	echo "start_switch: nobenega vmesnika eth1-eth3 - ali je topologija postavljena?" >&2
	exit 1
fi

if [ ! -f "$MODULE" ]; then
	echo "start_switch: modula $MODULE ni - pozeni ./common/build.sh" >&2
	exit 1
fi

mkdir -p "$SHARED"
cp "$BUILD"/steering.json "$BUILD"/steering.p4info.txtpb "$SHARED"/

echo "start_switch: ${PORTS[*]}"
exec simple_switch_grpc --device-id 0 --max-port-count 8 \
	"${PORTS[@]}" \
	--no-p4 \
	-- --grpc-server-addr 0.0.0.0:9559 --load-modules="$MODULE"
