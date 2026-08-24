#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

NAME=m2_stikalo
PURPOSE="Najvecja vzdrzna hitrost prestrezanja pri HTTP/3 v primerjavi s HTTP/2, v A in B.
Obe postavitvi izmeri isti program z istim prometom in istim iskanjem, zato je razlika med
njima natanko cena stikala v poti. Nobena krivulja ni prevzeta iz druge meritve."

. orodja/lib.sh

CELL_GROUPS=unknown

for topo in A0 B0; do
	echo "== $topo =="
	search_all "$topo"
done
finish
