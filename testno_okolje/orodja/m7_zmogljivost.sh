#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

NAME=m7_zmogljivost
PURPOSE="Najvecja vzdrzna hitrost po vrstah prometa. m1 in m3 iscejo mejo samo na prometu
unknown, torej na prometu, ki ga stikalo ne more razbremeniti, m5 pa meri pri stalni
obremenitvi pod nasicenjem, zato tam propustnost ne more biti razlicna. Ta meritev nasici
obhodni promet in edina izrazi razbremenitev v zmogljivosti in ne v porabi procesorja.
Meri se ip_white (cisti obhod) in sni_white (pri HTTP/2 obhoda ni, pri HTTP/3 je)."

. orodja/lib.sh

SEARCH_MAX="${SEARCH_MAX:-2048}"
CELL_MODES="${CELL_MODES:-ip_white sni_white}"

for topo in A0 B0; do
	echo "== $topo =="
	start_topo "$topo"
	BLOCK_FAILED=0
	for entry in $PROTOCOLS; do
		[ "$BLOCK_FAILED" = 1 ] && break
		proto="${entry%%:*}"
		share="${entry##*:}"
		for mode in $CELL_MODES; do
			[ "$BLOCK_FAILED" = 1 ] && break
			echo "  -- $proto / $mode --"
			CELL_GROUPS="$(groups_for "$mode")" \
				search_max "$topo" "$RESULTS/${topo}_${mode}/$proto" "$share" || true
		done
	done
	cleanup
done
finish
