#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

NAME=m6_prag
PURPOSE="Pri kolikem delezu obhodnega prometa se stikalo splaca. Model prag izracuna iz
cistih cen v m5, ta meritev pa ga potrdi: promet je mesanica pregledanega (unknown) in
obhodnega (sni_white) v delezih 25, 50 in 75 odstotkov. Ce izmerjene tocke lezijo na
napovedanih premicah, predpostavka o linearnosti drzi in prag je verodostojen."

. orodja/lib.sh

DURATION="${DURATION:-20}"
WARMUP="${WARMUP:-5}"
CELL_WORKERS=64
BYPASS="${BYPASS:-sni_white}"
SHARES="${SHARES:-25 50 75}"
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
		for pct in $SHARES; do
			[ "$BLOCK_FAILED" = 1 ] && break
			echo "  -- $proto / $pct % obhoda --"
			CELL_GROUPS="unknown:$((100 - pct)),$BYPASS:$pct" CELL_RATE_RPS="$rate" \
				cell "$topo" "$RESULTS/$topo/$proto/p$pct" "$share" || true
		done
	done
	cleanup
done
finish
