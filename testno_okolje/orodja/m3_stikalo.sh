#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

NAME=m3_stikalo
PURPOSE="Najvecja vzdrzna hitrost prestrezanja pri HTTP/3 v primerjavi s HTTP/2, v A in B.
Izmeri se B0 (odjemalec - stikalo - posrednik - streznik) z istim prometom in istim iskanjem
kot v m2, zato je razlika proti m2 natanko cena stikala v poti. Krivulja za A se prevzame
iz m2."

. orodja/lib.sh

CELL_GROUPS=unknown

search_all B0
finish
