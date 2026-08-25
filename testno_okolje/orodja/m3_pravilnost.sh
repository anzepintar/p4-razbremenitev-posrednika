#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

NAME=m3_pravilnost
PURPOSE="Ali je politika uveljavljena pravilno - pri posredniku in pri stikalu - v obeh
protokolih. Za vsako skupino prometa tece tok, ki je v celoti iz te skupine, pri nizki
frekvenci, da nasicenje ne skrije napak. Sodba se sestavi iz treh neodvisnih virov:
izida pri odjemalcu, stevcev stikala in dnevnika sej posrednika."

. orodja/lib.sh

DURATION="${DURATION:-12}"
WARMUP="${WARMUP:-3}"
CELL_WORKERS=32
RATE_RPS="${RATE_RPS:-20}"

for topo in A0 B0; do
	echo "== $topo =="
	start_topo "$topo"
	BLOCK_FAILED=0
	for entry in $PROTOCOLS; do
		[ "$BLOCK_FAILED" = 1 ] && break
		proto="${entry%%:*}"
		share="${entry##*:}"
		for mode in $MODES; do
			[ "$BLOCK_FAILED" = 1 ] && break
			echo "  -- $proto / $mode --"
			CELL_GROUPS="$(groups_for "$mode")" CELL_RATE_RPS="$RATE_RPS" \
				cell "$topo" "$RESULTS/$topo/$proto/$mode" "$share" || true
		done
	done
	cleanup
done
finish
