#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

NAME=m1_oprema
PURPOSE="Zgornja meja merilne opreme same, v obeh protokolih. Postavitev C0 je samo odjemalec
in streznik na neposredni povezavi, brez stikala in brez posrednika. Brez tega ni mogoce reci,
ali je omejitev v resitvi ali v odjemalcu; vse, kar dosezeta A in B, mora biti pod tem."

. orodja/lib.sh

CELL_GROUPS=other

tek() {
	search_all C0
}

run_all tek
