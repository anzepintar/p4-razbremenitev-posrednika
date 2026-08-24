#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

NAME=m6_prag
PURPOSE="Pri kolikem delezu obhodnega prometa je stikalo smiselno. Promet je mesanica
pregledanega (unknown) in obhodnega, posebej za beli IP in beli domenski seznam. Delez 0 in
100 odstotkov da cisti ceni, iz katerih se izpelje modelna premica, delezi 25, 50 in 75
odstotkov pa jo preverijo. Vse tocke so tako iz istega teka."

. orodja/lib.sh

DURATION="${DURATION:-20}"
WARMUP="${WARMUP:-5}"
CELL_WORKERS=64
MECHANISMS="${MECHANISMS:-ip_white sni_white}"
SHARES="${SHARES:-0 25 50 75 100}"

for topo in A0 B0; do
	echo "== $topo =="
	start_topo "$topo"
	BLOCK_FAILED=0
	for entry in $PROTOCOLS; do
		[ "$BLOCK_FAILED" = 1 ] && break
		proto="${entry%%:*}"
		share="${entry##*:}"
		rate="$(load_rate "$proto")"
		for mech in $MECHANISMS; do
			[ "$BLOCK_FAILED" = 1 ] && break
			for pct in $SHARES; do
				[ "$BLOCK_FAILED" = 1 ] && break
				echo "  -- $proto / $mech / $pct % obhoda --"
				CELL_GROUPS="unknown:$((100 - pct)),$mech:$pct" CELL_RATE_RPS="$rate" \
					cell "$topo" "$RESULTS/$topo/$proto/${mech}_p${pct}" "$share" || true
			done
		done
	done
	cleanup
done
finish
