#!/usr/bin/env bash
#   ./measure.sh latency "p4_baseline p4_full" 40 [--content-block]
#   ./measure.sh ramp "p4_full" "1 2 4 8 16" [--content-block]
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

USAGE='uporaba: measure.sh <latency|ramp> "<postavitve>" <zahtev|stopnje> [--content-block]'
KIND=""
TOPOS=""
STEPS=""
CONTENT=""

for arg in "$@"; do
	case "$arg" in
	--content-block) CONTENT="--content-block" ;;
	*)
		if [ -z "$KIND" ]; then KIND="$arg"
		elif [ -z "$TOPOS" ]; then TOPOS="$arg"
		else STEPS="$arg"; fi
		;;
	esac
done

case "$KIND" in
latency) [ -n "$STEPS" ] || STEPS=40 ;;
ramp) [ -n "$STEPS" ] || STEPS="1 2 4 8 16" ;;
*) echo "$USAGE" >&2; exit 2 ;;
esac
[ -n "$TOPOS" ] || { echo "$USAGE" >&2; exit 2; }

# Serija traja dolgo; brez tega gostitelj zaspi in v meritvi nastane vrzel.
if [ -z "${MEASURE_INHIBITED:-}" ] && command -v systemd-inhibit >/dev/null 2>&1; then
	export MEASURE_INHIBITED=1
	exec systemd-inhibit --what=idle:sleep:handle-lid-switch \
		--why="meritev testnega okolja" "$PWD/measure.sh" "$@"
fi

TOPO_DIR=..
OUT=out
SUDO="${SUDO-sudo}"
DURATION="${DURATION:-30}"
CURRENT=""
CONTENT_ARG=""
MITM_TOPOS="mitm_baseline mitm_controller p4_controller_mitm p4_full"

has_mitm() {
	case " $MITM_TOPOS " in
	*" $1 "*) return 0 ;;
	esac
	return 1
}

if [ "$KIND" = ramp ]; then
	SPEED="${SPEED:-1000}"
	export CLIENT_CPU="${CLIENT_CPU:-8}"
else
	SPEED="${SPEED:-4}"
	export CLIENT_CPU="${CLIENT_CPU:-2}"
fi

ARTEFACTS="metrics.jsonl summary.json alerts.jsonl controller.jsonl proxy_flows.jsonl"

cleanup() {
	if [ -n "$CURRENT" ]; then
		$SUDO clab destroy -t "$TOPO_DIR/$CURRENT.clab.yml" --cleanup >/dev/null 2>&1 || true
		CURRENT=""
	fi
}
trap cleanup EXIT

run() {
	local topo="$1" dest="$2"
	shift 2

	for file in $ARTEFACTS eve.json; do rm -f "$OUT/$file"; done
	rm -f "$OUT"/*.log

	CURRENT="$topo"
	./start.sh "$topo" $CONTENT_ARG

	clab exec -t "$TOPO_DIR/$topo.clab.yml" --label clab-node-name=client \
		--cmd "python3 -m runner --config /opt/traffic/scenario.yml $*"

	sleep 5
	if [ ! -s "$OUT/metrics.jsonl" ]; then
		echo "measure.sh: $topo ni dal meritev - poglej izpis 'clab exec' zgoraj." >&2
		exit 1
	fi

	mkdir -p "$dest"
	if [ "$KIND" = latency ]; then
		./ifstats.py "$topo" "$dest/ifstats.json"
	fi
	for file in $ARTEFACTS; do
		if [ -f "$OUT/$file" ]; then mv -f "$OUT/$file" "$dest/$file"; fi
	done
	echo "-> $dest/"
	cleanup
}

mkdir -p "$OUT"
for topo in $TOPOS; do
	name="$topo"
	CONTENT_ARG=""
	if [ -n "$CONTENT" ]; then
		if has_mitm "$topo"; then
			name="$topo-content"
			CONTENT_ARG="$CONTENT"
		else
			echo "measure.sh: $topo je brez posrednika, --content-block ne velja" >&2
		fi
	fi

	if [ "$KIND" = latency ]; then
		echo
		echo "== $name: $STEPS zahtev na odjemalca =="
		run "$topo" "$OUT/latency/$name" --requests "$STEPS" --speed "$SPEED"
	else
		for n in $STEPS; do
			echo
			echo "== $name: --parallel $n =="
			run "$topo" "$OUT/ramp/$name/p$n" \
				--duration "$DURATION" --speed "$SPEED" --parallel "$n"
		done
	fi
done

./plot.py
