#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

NAME=m5_vrste
PURPOSE="Vpliv stikala po vrstah prometa. A0 in B0 pri stalni obremenitvi pod nasicenjem;
tok je vsakic v celoti ene vrste, zato je cena te vrste cista in med postavitvama neposredno
primerljiva. Meri se propustnost, rokovanje in predvsem breme posrednika - CPU deljen s
stevilom POSLANIH zahtev, tudi tistih, ki posrednika sploh niso dosegle. Iz teh cistih cen
se v m6 izracuna prag rentabilnosti."

. orodja/lib.sh

DURATION="${DURATION:-20}"
WARMUP="${WARMUP:-5}"
CELL_WORKERS=64
RATE_H2="${RATE_H2:-80}"
RATE_H3="${RATE_H3:-10}"

# Obremenitev izpeljemo iz iskanja: 70 % manjsega od maksimumov, ki sta ju nasla m1 in m3,
# da obe postavitvi merita pri isti obremenitvi in obe varno pod nasicenjem.
load_rate() {
	local proto="$1" a b picked
	a="$(max_rps m1_posrednik A0 "$proto")"
	b="$(max_rps m3_stikalo B0 "$proto")"
	if [ -n "$a" ] && [ -n "$b" ]; then
		picked=$(python3 -c "print(max(1, int(min($a, $b) * 0.7)))")
		echo "$picked"
		return
	fi
	case "$proto" in
	h3) picked="$RATE_H3" ;;
	*) picked="$RATE_H2" ;;
	esac
	echo "$picked"
}

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
