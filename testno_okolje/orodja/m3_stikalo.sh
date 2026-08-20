#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

NAME=m3_stikalo
PURPOSE="Kaj stane stikalo, ko je v poti. Postavitev B0 (odjemalec - stikalo - posrednik -
streznik) z istim prometom in isto rampo kot m1, zato je razlika proti m1 natanko cena
stikala: koliko pade zgornja meja, koliko se podaljsa rokovanje in koliko procesorja porabi
stikalo samo, spet HTTP/2 proti HTTP/3."

. orodja/lib.sh

CELL_GROUPS=unknown

start_topo B0
for entry in $PROTOCOLS; do
	[ "$BLOCK_FAILED" = 1 ] && break
	proto="${entry%%:*}"
	share="${entry##*:}"
	echo "  -- $proto --"
	search_max B0 "$RESULTS/B0/$proto" "$share" || true
done
finish
