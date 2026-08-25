#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

NAME=splet_nabor
PURPOSE="Samo izbor nabora za pregled spleta, brez pregleda samega. Tece v postavitvi C1,
torej brez stikala in brez posrednika, in je isti izbor, kot ga na zacetku opravi splet.sh.
Uporaben je za pogled v osip nabora; meritev nabor vedno izbere sama, da med izborom in
pregledom ni odstopanj v okolju, casu ali izteku."

# shellcheck source=orodja/lib.sh
. orodja/lib.sh

SELECT_LIMIT="${SELECT_LIMIT:-0}"
SELECT_JOBS="${SELECT_JOBS:-64}"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-10}"
MAX_TIME="${MAX_TIME:-10}"
RETRIES="${RETRIES:-1}"

export PROBE_URL="${PROBE_URL:-https://www.cloudflare.com/}"

REMOTE=/opt/traffic/out/$NAME

bring_up() {
	local topo="$1"
	CURRENT="$topo"
	./orodja/start.sh "$topo"
	docker exec "clab-$topo-client" python3 -m probe --help >/dev/null 2>&1 || {
		echo "$NAME: probe v odjemalcu se ne zazene; pozeni ./orodja/build.sh" >&2
		return 1
	}
}

# Potek je v funkciji, ker ga lupina tako prebere in razcleni v enem kosu. Tek je dolg;
# brez tega bi ga urejanje datoteke med tekom pokvarilo na sredini.
main() {
	echo "== izbor v postavitvi C1: odjemalec - prehod, brez stikala in posrednika =="
	bring_up C1
	select_nabor C1 "$REMOTE"
	cleanup
	./orodja/reclaim.sh
}

main "$@"
