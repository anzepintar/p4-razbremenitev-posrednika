#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

MODE="${1:-matrix}"
case "$MODE" in
matrix | calibrate) ;;
*) echo "uporaba: measure.sh [matrix|calibrate]" >&2; exit 2 ;;
esac

OUT=out
SUDO="${SUDO-sudo}"
TOPO_DIR=..
CURRENT=""

if [ -z "${MEASURE_INHIBITED:-}" ] && command -v systemd-inhibit >/dev/null 2>&1; then
	export MEASURE_INHIBITED=1
	exec systemd-inhibit --what=idle:sleep:handle-lid-switch \
		--why="meritev testnega okolja" "$PWD/measure.sh" "$@"
fi

IFS='|' read -r TOPOLOGIES CASES MODES BACKGROUND_MBPS BACKGROUND_WORKERS \
	POLICY_RPS DURATION REPEATS TIMEOUT RAMP <<<"$(python3 - <<'PY'
import sys
sys.path.insert(0, ".")
import experiment as exp

e = exp.load()
print("|".join([
    " ".join(e.topologies),
    " ".join(f"{name}:{share}" for name, share in sorted(e.cases.items())),
    " ".join(e.modes),
    f"{e.background_mbps:g}",
    str(e.background_workers),
    f"{e.policy_rps:g}",
    str(e.duration_s),
    str(e.repeats),
    f"{e.connect_timeout_s:g}",
    " ".join(str(n) for n in e.ramp),
]))
PY
)"

POLICY_WORKERS=$(python3 -c \
	"import math,sys; print(math.ceil(float(sys.argv[1]) * float(sys.argv[2])) + 8)" \
	"$POLICY_RPS" "$TIMEOUT")

echo "postavitve: $TOPOLOGIES"
echo "protokoli:  $CASES"
if [ "$MODE" = calibrate ]; then
	echo "rampa:      $RAMP socasnih, trajanje ${DURATION}s"
else
	echo "nacini:     $MODES"
	echo "ozadje:     $BACKGROUND_MBPS Mb/s pri $BACKGROUND_WORKERS delavcih"
	echo "politika:   $POLICY_RPS zahtev/s pri $POLICY_WORKERS delavcih"
	echo "ponovitve:  $REPEATS x ${DURATION}s"
fi
echo

ARTEFACTS="metrics_ozadje.jsonl summary_ozadje.json \
	metrics_politika.jsonl summary_politika.json proxy_flows.jsonl"

cleanup() {
	if [ -n "$CURRENT" ]; then
		$SUDO clab destroy -t "$TOPO_DIR/$CURRENT.clab.yml" --cleanup >/dev/null 2>&1 || true
		CURRENT=""
	fi
}
trap cleanup EXIT

start_topo() {
	local topo="$1"
	CURRENT="$topo"
	./start.sh "$topo" --lazy --content-block

	if ! docker exec "clab-$topo-client" python3 -m runner --help >/dev/null 2>&1; then
		echo "measure.sh: runner v odjemalcu se ne zazene; zazeni ./common/build.sh" >&2
		docker exec "clab-$topo-client" python3 -m runner --help 2>&1 | tail -5 >&2
		return 1
	fi
}

collect_switch() {
	local topo="$1" dest="$2" name="$3"
	case "$topo" in
	B0 | B1)
		docker exec "clab-$topo-mitm" /opt/p4venv/bin/python /opt/traffic/proxy/steer.py \
			--grpc-addr 10.20.1.2:9559 --stats /opt/traffic/out/switch_stats.json \
			>>"$OUT/steer.log" 2>&1 || echo "    (stevcev stikala ni bilo mogoce prebrati)"
		[ -f "$OUT/switch_stats.json" ] && mv -f "$OUT/switch_stats.json" "$dest/$name"
		;;
	esac
}

client_run() {
	local topo="$1"
	shift
	clab exec -t "$TOPO_DIR/$topo.clab.yml" --label clab-node-name=client --cmd "$*"
}

run_cell() {
	local topo="$1" dest="$2" share="$3" mode="$4" ramp_workers="${5:-}"
	local base="python3 -m runner --config /opt/traffic/experiment.yml --quic-share $share"
	local pids="" load="--rate-mbps $BACKGROUND_MBPS --workers $BACKGROUND_WORKERS"

	[ -n "$ramp_workers" ] && load="--workers $ramp_workers"

	for file in $ARTEFACTS; do rm -f "$OUT/$file"; done
	mkdir -p "$dest"

	./nodestats.py links "$topo" "$dest/links_before.json"
	collect_switch "$topo" "$dest" switch_before.json
	./nodestats.py sample "$topo" "$dest/nodes.json" &
	local sampler=$!

	client_run "$topo" "$base --groups unknown $load \
		--duration $DURATION --label ozadje" 2>&1 | sed 's/^/    ozadje:   /' &
	pids="$pids $!"

	if [ "$mode" != brez ]; then
		client_run "$topo" "$base --groups $mode --rate-rps $POLICY_RPS \
			--workers $POLICY_WORKERS --duration $DURATION --label politika" \
			2>&1 | sed 's/^/    politika: /' &
		pids="$pids $!"
	fi

	for pid in $pids; do wait "$pid" 2>/dev/null || true; done

	kill -TERM "$sampler" 2>/dev/null || true
	wait "$sampler" 2>/dev/null || true

	./nodestats.py links "$topo" "$dest/links_after.json"
	collect_switch "$topo" "$dest" switch_after.json

	for file in $ARTEFACTS; do
		[ -f "$OUT/$file" ] && mv -f "$OUT/$file" "$dest/$file"
	done
	[ -s "$dest/metrics_ozadje.jsonl" ] || { echo "measure.sh: $dest brez meritev" >&2; return 1; }
}

check_groups() {
	python3 - "$@" <<'PY'
import json
import sys
from pathlib import Path

data = json.loads(Path("lists/assignment.json").read_text(encoding="utf-8"))
have = {info["group"] for info in data["domains"].values()}
missing = [group for group in sys.argv[1:] if group != "brez" and group not in have]
if missing:
    print(f"measure.sh: razdelitev nima skupin {', '.join(missing)};", file=sys.stderr)
    print("  popravi domains.groups v experiment.yml in pozeni ./common/gen_lists.py",
          file=sys.stderr)
    raise SystemExit(1)
PY
}

measure_matrix() {
	local rep topo entry case_name share mode
	for rep in $(seq 1 "$REPEATS"); do
		for topo in $TOPOLOGIES; do
			echo "== ponovitev $rep / $topo =="
			start_topo "$topo"
			for entry in $CASES; do
				case_name="${entry%%:*}"
				share="${entry##*:}"
				for mode in $MODES; do
					echo "  -- $case_name / $mode --"
					run_cell "$topo" "$OUT/matrix/r$rep/$topo/$case_name/$mode" \
						"$share" "$mode" || true
				done
			done
			cleanup
		done
	done
}

measure_calibrate() {
	local topo entry case_name share workers
	for topo in $TOPOLOGIES; do
		echo "== $topo: rampa =="
		start_topo "$topo"
		for entry in $CASES; do
			case_name="${entry%%:*}"
			share="${entry##*:}"
			for workers in $RAMP; do
				echo "  -- $case_name / $workers socasnih --"
				run_cell "$topo" "$OUT/calibrate/$topo/$case_name/w$workers" \
					"$share" brez "$workers" || true
			done
		done
		cleanup
	done
}

mkdir -p "$OUT"
if [ "$MODE" = calibrate ]; then
	check_groups unknown
	measure_calibrate
else
	check_groups $MODES unknown
	measure_matrix
fi

./plot.py
