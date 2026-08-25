#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

NAME=splet
PURPOSE="Ali prestrezanje zdrzi na pravem spletu. Nabor se izbere na zacetku, v isti
postavitvi C1 in z istimi izteki kot pregled, zato med izborom in meritvijo ni odstopanj.
Pregled nato vzame vzorec SAMPLE domen, ki delujejo po obeh protokolih; vzorec doloca seme,
zato vsi bloki obeh postavitev vidijo iste domene. Najprej izhodisce v C1, torej brez stikala
in brez posrednika, nato isti vzorec skozi B1. Odstotek v porocilu je delez strani, ki
delujejo v B1, med tistimi, ki delujejo ze v izhodiscu."

# shellcheck source=orodja/lib.sh
. orodja/lib.sh

SWEEP_CLIENTS="${SWEEP_CLIENTS:-curl chromium firefox}"
SWEEP_PROTOS="${SWEEP_PROTOS:-h2 h3}"
LIMIT="${LIMIT:-0}"
SAMPLE="${SAMPLE:-100}"
SEED="${SEED:-1234}"
KEEP="${KEEP:-1}"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-10}"
MAX_TIME="${MAX_TIME:-10}"
PAGE_TIMEOUT="${PAGE_TIMEOUT:-15}"
RETRIES="${RETRIES:-1}"
NO_KYBER="${NO_KYBER:-0}"

export PROBE_URL="${PROBE_URL:-https://www.cloudflare.com/}"

REMOTE=/opt/traffic/out/$NAME

bring_up() {
	local topo="$1"
	shift
	CURRENT="$topo"
	./orodja/start.sh "$topo" "$@"
	docker exec "clab-$topo-client" python3 -m probe --help >/dev/null 2>&1 || {
		echo "$NAME: probe v odjemalcu se ne zazene; pozeni ./orodja/build.sh" >&2
		return 1
	}
}

probe() {
	local topo="$1" client="$2" proto="$3"
	docker exec "clab-$topo-client" python3 -m probe \
		--client "$client" --proto "$proto" --phase "$topo" \
		--targets "$REMOTE/nabor.json" \
		--out "$REMOTE/$topo/probes_${client}_${proto}.jsonl" \
		--limit "$LIMIT" --sample "$SAMPLE" --seed "$SEED" \
		--connect-timeout "$CONNECT_TIMEOUT" \
		--max-time "$MAX_TIME" \
		--page-timeout "$PAGE_TIMEOUT" \
		--retries "$RETRIES" \
		$([ "$NO_KYBER" = 1 ] && echo --no-kyber) 2>&1 | sed 's/^/    /'
}

sweep() {
	local topo="$1" client proto
	mkdir -p "$RESULTS/$topo"
	for client in $SWEEP_CLIENTS; do
		for proto in $SWEEP_PROTOS; do
			collect_switch "$topo" "$RESULTS/$topo" "switch_${client}_${proto}_before.json" || true
			probe "$topo" "$client" "$proto"
			collect_switch "$topo" "$RESULTS/$topo" "switch_${client}_${proto}_after.json" || true
		done
	done
}

# Celoten potek je v funkciji, ker ga lupina tako prebere in razcleni v enem kosu.
# Skripta tece dolgo; brez tega bi jo urejanje med tekom pokvarilo sredi pregleda.
main() {
	echo "== izhodisce C1: odjemalec - prehod, brez stikala in posrednika =="
	bring_up C1

	echo "  izbor nabora"
	select_nabor C1 "$REMOTE"
	check_lists

	sweep C1
	cleanup

	echo
	echo "== pregled B1: odjemalec - stikalo - posrednik - prehod =="
	# Dnevnik sej se dopisuje, zato ga pred B1 pobrisemo.
	rm -f "$OUT/proxy_flows.jsonl"
	bring_up B1 --no-content-block
	sweep B1
	cp -f "$OUT/proxy_flows.jsonl" "$RESULTS/B1/proxy_flows.jsonl" 2>/dev/null || true

	./orodja/reclaim.sh
	echo
	./orodja/splet_report.py "$RESULTS"

	if [ "$KEEP" = 1 ]; then
		CURRENT=""
		echo
		echo "B1 tece naprej, za rocno analizo nedelujocih strani:"
		echo "  ./orodja/browse.sh B1 chromium https://<domena>/"
		echo "  FORCE_QUIC=1 ./orodja/browse.sh B1 firefox https://<domena>/"
		echo "  sudo clab destroy -t B1.clab.yml --cleanup"
	fi
}

main "$@"
