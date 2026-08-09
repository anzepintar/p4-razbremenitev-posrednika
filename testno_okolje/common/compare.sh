#!/usr/bin/env bash
#   ./compare.sh [stevilo_zahtev_na_odjemalca] [zagoni]
#   ./compare.sh 40 ADG      # samo izbrani zagoni
#   Rezultati gredo v out/<zagon>/, povzetek naredi compare.py.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

REQUESTS="${1:-40}"
WANTED="${2:-ABCDEFGH}"
SPEED="${SPEED:-4}"

if [ -z "${COMPARE_INHIBITED:-}" ] && command -v systemd-inhibit >/dev/null 2>&1; then
	export COMPARE_INHIBITED=1
	exec systemd-inhibit --what=idle:sleep:handle-lid-switch \
		--why="meritev testnega okolja" "$PWD/$(basename "${BASH_SOURCE[0]}")" "$@"
fi
TOPO_DIR=..
OUT=out
SUDO="${SUDO-sudo}"
CURRENT=""

ARTEFACTS="metrics.jsonl summary.json verdicts.jsonl alerts.jsonl controller.jsonl bypass.jsonl proxy_flows.jsonl eve.json"

ifstats() {
	local topo="$1" target="$2"
	python3 - "$topo" "$target" <<'PY'
import json, subprocess, sys

topo, target = sys.argv[1], sys.argv[2]
out = {}
for node in ("client", "mitm"):
    name = f"clab-{topo}-{node}"
    try:
        raw = subprocess.run(["docker", "exec", name, "ip", "-s", "-j", "link", "show", "eth1"],
                             capture_output=True, text=True, timeout=20, check=True).stdout
        link = json.loads(raw)[0]
        out[node] = {
            "rx_packets": link["stats64"]["rx"]["packets"],
            "rx_bytes": link["stats64"]["rx"]["bytes"],
            "tx_packets": link["stats64"]["tx"]["packets"],
            "tx_bytes": link["stats64"]["tx"]["bytes"],
        }
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, KeyError, ValueError, IndexError):
        continue


def counted(chain):
    raw = subprocess.run(
        ["docker", "exec", f"clab-{topo}-mitm", "iptables", "-nvx", "-L", chain],
        capture_output=True, text=True, timeout=20, check=True).stdout
    # Pravilo brez akcije pusti stolpec 'target' prazen, zato se na fiksne indekse ni
    # mogoce zanesti; stevca sta vedno prvi dve polji vrstice z nasim naslovom.
    for line in raw.splitlines():
        parts = line.split()
        if "10.0.1.0/24" in parts and parts[0].isdigit():
            return {"packets": int(parts[0]), "bytes": int(parts[1])}
    return None


if "mitm" in out:
    try:
        out["intercepted"] = counted("INPUT")
        out["passthrough"] = counted("FORWARD")
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError, IndexError):
        pass

with open(target, "w", encoding="utf-8") as handle:
    json.dump(out, handle, indent=2)
PY
}

cleanup() {
	if [ -n "$CURRENT" ]; then
		$SUDO clab destroy -t "$TOPO_DIR/$CURRENT.clab.yml" --cleanup >/dev/null 2>&1 || true
		CURRENT=""
	fi
}
trap cleanup EXIT

topo_of() {
	case "$1" in
	A) echo client_server ;;
	B | C) echo mitm_baseline ;;
	D) echo p4_baseline ;;
	E) echo p4_controller_mitm ;;
	F) echo p4_controller_ids ;;
	G) echo p4_full ;;
	H) echo mitm_controller ;;
	esac
}

label_of() {
	case "$1" in
	A) echo "brez posrednika" ;;
	B) echo "posrednik brez pregleda vsebine" ;;
	C) echo "posrednik s pregledom vsebine" ;;
	D) echo "stikalo P4 brez odlocanja" ;;
	E) echo "P4 s preusmerjanjem na posrednik" ;;
	F) echo "P4 z zrcaljenjem na IDS" ;;
	G) echo "resitev: IDS, zanka zaupanja in posrednik" ;;
	H) echo "izbirni pregled brez P4, odloca krmilnik" ;;
	esac
}

run() {
	local name="$1" topo
	topo=$(topo_of "$name")

	echo
	echo "== $name: $(label_of "$name") ($topo) =="
	# Dnevniki se dopisujejo, zato jih pred vsakim zagonom pocistimo.
	for file in $ARTEFACTS; do rm -f "$OUT/$file"; done
	rm -f "$OUT"/*.log

	CURRENT="$topo"
	if [ "$name" = "C" ] || [ "$name" = "G" ] || [ "$name" = "H" ]; then
		./start.sh "$topo" --content-block
	else
		./start.sh "$topo"
	fi

	clab exec -t "$TOPO_DIR/$topo.clab.yml" --label clab-node-name=client \
		--cmd "python3 -m runner --config /opt/traffic/scenario.yml --requests $REQUESTS --speed $SPEED"

	sleep 5
	mkdir -p "$OUT/$name"
	ifstats "$topo" "$OUT/$name/ifstats.json"
	for file in $ARTEFACTS; do
		[ -f "$OUT/$file" ] && mv -f "$OUT/$file" "$OUT/$name/$file"
	done
	echo "zagon $name -> $OUT/$name/"
	cleanup
}

for name in $(echo "$WANTED" | grep -o .); do
	case "$name" in
	[A-H]) run "$name" ;;
	*) echo "compare.sh: neznan zagon '$name'" >&2; exit 2 ;;
	esac
done

./compare.py --out "$OUT"
./plot.py --out "$OUT"
