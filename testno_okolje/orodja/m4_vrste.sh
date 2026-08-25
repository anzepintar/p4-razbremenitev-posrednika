#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

NAME=m4_vrste
PURPOSE="Vpliv stikala po posameznih vrstah prometa. A0 in B0 pri stalni obremenitvi pod
nasicenjem, isti za obe postavitvi; tok je vsakic v celoti ene vrste, zato je cena te vrste
cista in med postavitvama neposredno primerljiva. Celica traja 20 s, pred njo pa tece ogrevanje,
da posrednik izda potrdila vseh strani. Meri se breme posrednika - CPU deljen s stevilom
POSLANIH zahtev, tudi tistih, ki posrednika sploh niso dosegle. Iz teh cistih cen se v m6
izracuna prag rentabilnosti."

# Trije obhodi nabora, da ogrevanje pokrije tudi domene, ki jih nakljucni izbor sicer izpusti.
WARMUP_REQUESTS="${WARMUP_REQUESTS:-300}"

. orodja/lib.sh

DURATION="${DURATION:-20}"
WARMUP="${WARMUP:-0}"
CELL_WORKERS=64

for topo in A0 B0; do
	echo "== $topo =="
	start_topo "$topo"
	BLOCK_FAILED=0
	for entry in $PROTOCOLS; do
		[ "$BLOCK_FAILED" = 1 ] && break
		proto="${entry%%:*}"
		share="${entry##*:}"
		rate="$(load_rate "$proto")"
		for mode in $MODES; do
			[ "$BLOCK_FAILED" = 1 ] && break
			echo "  -- $proto / $mode pri $rate zahtevah/s --"
			CELL_GROUPS="$(groups_for "$mode")" CELL_RATE_RPS="$rate" \
				cell "$topo" "$RESULTS/$topo/$proto/$mode" "$share" || true
		done
	done
	cleanup
done
finish
