#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

NAME=m1_posrednik
PURPOSE="Kako se nas fork mitmproxy obnese pri HTTP/3 v primerjavi s HTTP/2. Postavitev A0
(odjemalec - posrednik - streznik), promet samo iz skupine unknown, torej brez politike, da
se meri cisto prestrezanje. Rampa socasnosti pokaze zgornjo mejo propustnosti, podaljsanje
rokovanja in porabo procesorja posrednika na zahtevo."

. orodja/lib.sh

CELL_GROUPS=unknown

start_topo A0
for entry in $PROTOCOLS; do
	[ "$BLOCK_FAILED" = 1 ] && break
	proto="${entry%%:*}"
	share="${entry##*:}"
	echo "  -- $proto --"
	search_max A0 "$RESULTS/A0/$proto" "$share" || true
done
finish
