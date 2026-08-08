#!/usr/bin/env bash
set -euo pipefail

RULES="${RULES:-/opt/traffic/ids/testset.rules}"
OUT="${OUT:-/opt/traffic/out}"
IFACE="${IFACE:-eth1}"

ip link set dev "$IFACE" up
ip link set dev "$IFACE" promisc on
ethtool -K "$IFACE" rx off tx off sg off tso off gso off gro off lro off >/dev/null 2>&1 || true

if [ ! -s "$RULES" ]; then
	echo "start_ids: pravil ni v $RULES - pozeni common/ids/gen_rules.py" >&2
	exit 1
fi

mkdir -p "$OUT"

# -k none: pakete klonira bmv2, zato kontrolne vsote niso merodajne.
exec suricata -i "$IFACE" -S "$RULES" -k none \
	--set default-log-dir="$OUT" \
	--set app-layer.protocols.quic.enabled=yes
