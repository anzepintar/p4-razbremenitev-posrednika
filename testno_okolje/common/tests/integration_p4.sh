#!/usr/bin/env bash
set -euo pipefail

COMMON="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOPO_DIR="$(cd "$COMMON/.." && pwd)"
SUDO="${SUDO-sudo}"
REQUESTS="${1:-3}"
SPEED="${SPEED:-6}"
FAILURES=0
TOPO=""

ARTEFACTS="metrics.jsonl summary.json verdicts.jsonl alerts.jsonl controller.jsonl eve.json"

cleanup() {
	[ -n "$TOPO" ] && $SUDO clab destroy -t "$TOPO_DIR/$TOPO.clab.yml" --cleanup >/dev/null 2>&1 || true
}
trap cleanup EXIT

ok() { printf '  \033[32mok\033[0m   %s\n' "$1"; }
fail() {
	printf '  \033[31mFAIL\033[0m %s\n' "$1"
	FAILURES=$((FAILURES + 1))
}
check() { [ "$2" = "$3" ] && ok "$1" || fail "$1: pricakovano '$3', dobljeno '$2'"; }

sw() { docker exec -i "clab-$TOPO-switch" "$@"; }

counter() {
	sw simple_switch_CLI 2>/dev/null <<<"counter_read stats $1" |
		sed -n 's/.*, \([0-9]*\) packets.*/\1/p'
}

start() {
	TOPO="$1"
	shift
	for file in $ARTEFACTS; do rm -f "$COMMON/out/$file"; done
	rm -f "$COMMON/out"/*.log
	SUDO="$SUDO" "$COMMON/start.sh" "$TOPO" "$@" >/dev/null && ok "$TOPO stoji in tece" || {
		fail "$TOPO se ni zagnal"
		exit 1
	}
}

run_traffic() {
	clab exec -t "$TOPO_DIR/$TOPO.clab.yml" --label clab-node-name=client \
		--cmd "python3 -m runner --config /opt/traffic/scenario.yml --requests $REQUESTS --speed $SPEED" \
		>/dev/null 2>&1
	sleep 5
}

check_metrics() {
	local tolerance="${1:-0}"
	read -r rows errors protos <<<"$(python3 - "$COMMON/out/metrics.jsonl" <<'PY'
import json, sys
rows = [json.loads(line) for line in open(sys.argv[1]) if line.strip()]
errors = sum(1 for r in rows if r.get("exitcode") != 0)
print(len(rows), errors, len({r.get("proto") for r in rows}))
PY
	)"
	[ "$rows" -gt 0 ] && ok "runner je zapisal $rows vrstic" || fail "metrics.jsonl je prazen"
	[ "$errors" -le "$tolerance" ] &&
		ok "odpovedanih povezav: $errors (dovoljeno $tolerance)" ||
		fail "odpovedalo je $errors povezav, dovoljeno $tolerance"
	check "oba protokola (h2 in h3) prideta skozi" "$protos" "2"
}

echo "== p4_baseline =="
start p4_baseline

dump=$(sw simple_switch_CLI 2>/dev/null <<<"table_dump steering")
grep -q "SwitchIngress.direct" <<<"$dump" && ok "steering privzeto 'direct'" ||
	fail "steering nima privzete akcije 'direct'"

run_traffic
check_metrics
check "nic zavrzenega zaradi manjkajoce poti" "$(counter 1)" "0"
check "nic zavrzenega zaradi TTL" "$(counter 2)" "0"
cleanup

echo
echo "== p4_controller_mitm =="
start p4_controller_mitm

dump=$(sw simple_switch_CLI 2>/dev/null <<<"table_dump SwitchIngress.steering")
check "krmilnik je vpisal tri vnose" "$(grep -c 'Dumping entry' <<<"$dump")" "3"
grep -q "SwitchIngress.via_mitm" <<<"$dump" && ok "vnos za nizko zaupanje kaze na mitm" ||
	fail "v steering ni akcije via_mitm"

PCAP=/opt/traffic/out/${TOPO}-mitm.pcap
docker exec -d "clab-$TOPO-mitm" tcpdump -i eth1 -w "$PCAP" -U 'tcp port 443 or udp port 443'
sleep 2
run_traffic
check_metrics
# tcpdump -U pise sproti, zato ga ni treba ustaviti (slika nima pkill).
seen=$(docker exec "clab-$TOPO-mitm" tcpdump -r "$PCAP" -nn 2>/dev/null |
	grep -oE '10\.0\.1\.[0-9]+' | sort -u | paste -sd, -)
check "na posrednika pride samo nizko zaupanje" "$seen" "10.0.1.12"
cleanup

echo
echo "== p4_controller_ids =="
start p4_controller_ids

dump=$(sw simple_switch_CLI 2>/dev/null <<<"table_dump SwitchIngress.steering")
check "vnosi za obe smeri" "$(grep -c 'SwitchIngress.mirror' <<<"$dump")" "6"
sw simple_switch_CLI 2>/dev/null <<<"mirroring_get 100" | grep -q "MirroringSessionConfig" &&
	ok "klonirna seja 100 obstaja" || fail "klonirne seje 100 ni"

run_traffic
check_metrics

read -r alerts missed fronted <<<"$(python3 - "$COMMON/out" <<'PY'
import json, sys
from pathlib import Path

out = Path(sys.argv[1])
rows = [json.loads(l) for l in (out / "metrics.jsonl").read_text().splitlines() if l.strip()]
alerts = [json.loads(l) for l in (out / "alerts.jsonl").read_text().splitlines() if l.strip()]

detected = {a["sni"] for a in alerts}
expected = {r["sni"] for r in rows if r.get("category") == "phishing" and not r.get("fronting")}
# Pri frontanju je SNI legitimna domena, zato IDS zanjo ne more imeti zaznave.
fronted_sni = {r["sni"] for r in rows if r.get("fronting")}
print(len(alerts), len(expected - detected), len(fronted_sni & detected))
PY
)"
[ "$alerts" -gt 0 ] && ok "IDS je javil $alerts zaznav" || fail "alerts.jsonl je prazen"
check "nobena nefrontana phishing domena ni zgresena" "$missed" "0"
check "frontane domene IDS ne vidi (slepa pega po zasnovi)" "$fronted" "0"
check "krmilnik je zaznave prejel" \
	"$(grep -c '"source": "demote"' "$COMMON/out/controller.jsonl")" "$alerts"
cleanup

echo
echo "== p4_full =="
start p4_full --content-block

dump=$(sw simple_switch_CLI 2>/dev/null <<<"table_dump SwitchIngress.steering")
check "zacetno stanje: dva zrcaljena odjemalca" \
	"$(grep -c 'SwitchIngress.mirror' <<<"$dump")" "5"

run_traffic
# p4_full je najtezja postavitev (kloniranje obeh smeri, posrednik in Suricata
# hkrati), zato tu in tam izpade posamezno nalaganje strani prek QUIC.
check_metrics 5

read -r demotions changed fronted unblocked <<<"$(python3 - "$COMMON/out" <<'PY'
import json, sys
from pathlib import Path

out = Path(sys.argv[1])
rows = [json.loads(l) for l in (out / "metrics.jsonl").read_text().splitlines() if l.strip()]
ctl = [json.loads(l) for l in (out / "controller.jsonl").read_text().splitlines() if l.strip()]

demotions = [c for c in ctl if c.get("source") == "demote"]
changed = [c for c in demotions if c.get("changed")]
# Frontanje doseze skrito stran le, kadar sta krinka in skrita domena na istem
# naslovu; takrat mora pregled vsebine zahtevo blokirati.
fronted = [r for r in rows if r.get("fronting") and r.get("category") == "phishing"]
print(len(demotions), len(changed), len(fronted), sum(1 for r in fronted if not r.get("blocked")))
PY
)"
[ "$demotions" -gt 0 ] && ok "IDS je sprozil $demotions znizanj zaupanja" ||
	fail "v controller.jsonl ni vrstice 'demote'"
[ "$changed" -gt 0 ] && ok "$changed odjemalcev je zamenjalo pot" ||
	fail "nobeno znizanje ni spremenilo poti"
grep -q "SwitchIngress.via_mitm" \
	<<<"$(sw simple_switch_CLI 2>/dev/null <<<"table_dump SwitchIngress.steering")" &&
	ok "prepis poti je viden na stikalu" || fail "na stikalu ni akcije via_mitm"
check "vse frontane phishing zahteve ($fronted) so blokirane po vsebini" "$unblocked" "0"
cleanup

echo
[ "$FAILURES" -eq 0 ] && echo "vse v redu" || echo "$FAILURES neuspesnih preverjanj"
exit "$FAILURES"
