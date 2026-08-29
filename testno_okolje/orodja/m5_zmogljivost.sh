#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

NAME=m5_zmogljivost
PURPOSE="Najvecja hitrost prehoda prometa v A in B, za tri skupine prometa, ki lahko gredo
cez. m4 meri pri stalni obremenitvi pod nasicenjem, zato tam propustnost ne more biti
razlicna. Ta meritev nasici vsako skupino prometa posebej in edina izrazi razbremenitev v
zmogljivosti in ne v porabi procesorja. Izhodisce ostali promet izmeri sama, da so vsi stolpci
iz istega teka."

. orodja/lib.sh

SEARCH_MAX="${SEARCH_MAX:-2048}"
CELL_MODES="${CELL_MODES:-other ip_white sni_white}"

tek() {
	local topo entry proto share mode
	for topo in A0 B0; do
		[ "$BLOCK_FAILED" = 1 ] && break
		echo "== $topo =="
		start_topo "$topo"
		for entry in $PROTOCOLS; do
			[ "$BLOCK_FAILED" = 1 ] && break
			proto="${entry%%:*}"
			share="${entry##*:}"
			for mode in $CELL_MODES; do
				[ "$BLOCK_FAILED" = 1 ] && break
				echo "  -- $proto / $mode --"
				CELL_GROUPS="$mode" \
					search_max "$topo" "$RESULTS/${topo}_${mode}/$proto" "$share" || true
			done
		done
		cleanup
	done
}

run_all tek
