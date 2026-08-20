#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

NAME=m4_referenca
PURPOSE="Referencna zgornja meja brez vsega. Postavitev C0 je samo odjemalec in streznik na
neposredni povezavi, brez stikala in brez posrednika. Pove, kaj zmore merilna oprema sama;
brez tega ni mogoce reci, ali je omejitev v reseni ali v odjemalcu. Vse, kar dosezeta A0 in
B0, mora biti pod tem."

. orodja/lib.sh

CELL_GROUPS=unknown

start_topo C0
for entry in $PROTOCOLS; do
	[ "$BLOCK_FAILED" = 1 ] && break
	proto="${entry%%:*}"
	share="${entry##*:}"
	echo "  -- $proto --"
	search_max C0 "$RESULTS/C0/$proto" "$share" || true
done
finish
