#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

NAME=m2_prestrezanje
PURPOSE="Cena prestrezanja pri HTTP/3 v primerjavi s HTTP/2. Postavitev A0 (odjemalec -
posrednik - streznik), promet samo iz skupine unknown, torej brez politike, da se meri cisto
prestrezanje."

. orodja/lib.sh

CELL_GROUPS=unknown

search_all A0
finish
