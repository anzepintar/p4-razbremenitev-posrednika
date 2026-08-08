#!/usr/bin/env bash
set -euo pipefail

COMMON="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOPO_DIR="$(cd "$COMMON/.." && pwd)"
SUDO="${SUDO-sudo}"
REQUESTS="${1:-3}"
FAILURES=0
TOPO=""

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

wait_for() {
	local node="$1" port="$2"
	for _ in $(seq 1 30); do
		docker exec "clab-$TOPO-$node" ss -lntu 2>/dev/null | grep -q ":$port" && return 0
		sleep 1
	done
	return 1
}

start_switch() {
	local pipeline="${1:-0}"
	mkdir -p "$COMMON/out"
	docker exec -d "clab-$TOPO-switch" sh -c \
		"exec env NO_PIPELINE=$pipeline /opt/switch/start_switch.sh >>/opt/traffic/out/switch.log 2>&1"
	wait_for switch 9559 && ok "bmv2 posluša na 9559" || {
		fail "bmv2 se ni zagnal"
		sed 's/^/    /' "$COMMON/out/switch.log" >&2 || true
		exit 1
	}
}

run_traffic() {
	clab exec -t "$TOPO_DIR/$TOPO.clab.yml" --label clab-node-name=server \
		--cmd "caddy start --config /opt/traffic/server/Caddyfile" >/dev/null 2>&1
	"$COMMON/trust.sh" "$TOPO" >/dev/null
	rm -f "$COMMON/out/metrics.jsonl" "$COMMON/out/summary.json"
	clab exec -t "$TOPO_DIR/$TOPO.clab.yml" --label clab-node-name=client \
		--cmd "python3 -m runner --config /opt/traffic/scenario.yml --requests $REQUESTS" >/dev/null 2>&1
}

check_metrics() {
	read -r rows errors protos <<<"$(python3 - "$COMMON/out/metrics.jsonl" <<'PY'
import json, sys
rows = [json.loads(line) for line in open(sys.argv[1]) if line.strip()]
errors = sum(1 for r in rows if r.get("exitcode") != 0)
print(len(rows), errors, len({r.get("proto") for r in rows}))
PY
	)"
	[ "$rows" -gt 0 ] && ok "runner je zapisal $rows vrstic" || fail "metrics.jsonl je prazen"
	check "vse zahteve so uspele" "$errors" "0"
	check "oba protokola (h2 in h3) prideta skozi" "$protos" "2"
}

echo "== p4_baseline =="
TOPO=p4_baseline
$SUDO clab deploy -t "$TOPO_DIR/$TOPO.clab.yml" --reconfigure >/dev/null
ok "topologija stoji"
start_switch 0

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
TOPO=p4_controller_mitm
$SUDO clab deploy -t "$TOPO_DIR/$TOPO.clab.yml" --reconfigure >/dev/null
ok "topologija stoji"
start_switch 1

docker exec -d "clab-$TOPO-controller" sh -c \
	'exec python3 /opt/traffic/controller/controller.py --grpc-addr 10.20.1.2:9559 --policy mitm \
	 >>/opt/traffic/out/controller.log 2>&1'
wait_for controller 8080 && ok "krmilnik posluša na 8080" || {
	fail "krmilnik se ni zagnal"
	sed 's/^/    /' "$COMMON/out/controller.log" >&2 || true
	exit 1
}

dump=$(sw simple_switch_CLI 2>/dev/null <<<"table_dump SwitchIngress.steering")
check "krmilnik je vpisal tri vnose" "$(grep -c 'Dumping entry' <<<"$dump")" "3"
grep -q "SwitchIngress.via_mitm" <<<"$dump" && ok "vnos za nizko zaupanje kaze na mitm" ||
	fail "v steering ni akcije via_mitm"

clab exec -t "$TOPO_DIR/$TOPO.clab.yml" --label clab-node-name=server \
	--cmd "caddy start --config /opt/traffic/server/Caddyfile" >/dev/null 2>&1
"$COMMON/trust.sh" "$TOPO" >/dev/null
docker exec -d "clab-$TOPO-mitm" sh -c 'exec mitmdump "$@" >>/opt/traffic/out/mitm.log 2>&1' _ \
	--set confdir=/data/mitmproxy \
	--set ssl_verify_upstream_trusted_ca=/opt/traffic/pki/trust.pem \
	--set keep_host_header=true \
	-s /opt/proxy/sni_passthrough.py \
	--mode reverse:https://10.0.2.10:443@8443 \
	--mode reverse:https://10.0.2.11:443@8444 \
	--mode reverse:https://10.0.2.12:443@8445
for _ in $(seq 1 60); do
	docker exec "clab-$TOPO-mitm" test -s /data/mitmproxy/mitmproxy-ca-cert.pem 2>/dev/null && break
	sleep 1
done
"$COMMON/trust.sh" "$TOPO" >/dev/null
wait_for mitm 8443 && ok "posrednik posluša" || fail "posrednik se ni zagnal"

PCAP=/opt/traffic/out/${TOPO}-mitm.pcap
docker exec -d "clab-$TOPO-mitm" tcpdump -i eth1 -w "$PCAP" -U 'tcp port 443 or udp port 443'
sleep 2
run_traffic
sleep 2

check_metrics
# tcpdump -U pise sproti, zato ga ni treba ustaviti (slika nima pkill).
seen=$(docker exec "clab-$TOPO-mitm" tcpdump -r "$PCAP" -nn 2>/dev/null |
	grep -oE '10\.0\.1\.[0-9]+' | sort -u | paste -sd, -)
check "na posrednika pride samo nizko zaupanje" "$seen" "10.0.1.12"
cleanup

echo
echo "== p4_controller_ids =="
TOPO=p4_controller_ids
$SUDO clab deploy -t "$TOPO_DIR/$TOPO.clab.yml" --reconfigure >/dev/null
ok "topologija stoji"
start_switch 1

rm -f "$COMMON/out/eve.json" "$COMMON/out/alerts.jsonl" "$COMMON/out/controller.jsonl"
docker exec -d "clab-$TOPO-controller" sh -c \
	'exec python3 /opt/traffic/controller/controller.py --grpc-addr 10.20.1.2:9559 --policy ids \
	 >>/opt/traffic/out/controller.log 2>&1'
wait_for controller 8080 && ok "krmilnik posluša na 8080" || {
	fail "krmilnik se ni zagnal"
	exit 1
}

dump=$(sw simple_switch_CLI 2>/dev/null <<<"table_dump SwitchIngress.steering")
check "vnosi za obe smeri" "$(grep -c 'SwitchIngress.mirror' <<<"$dump")" "6"
sw simple_switch_CLI 2>/dev/null <<<"mirroring_get 100" | grep -q "MirroringSessionConfig" &&
	ok "klonirna seja 100 obstaja" || fail "klonirne seje 100 ni"

docker exec -d "clab-$TOPO-ids" sh -c 'exec /opt/ids/start_ids.sh >>/opt/traffic/out/ids.log 2>&1'
for _ in $(seq 1 40); do
	[ -s "$COMMON/out/eve.json" ] && break
	sleep 1
done
[ -s "$COMMON/out/eve.json" ] && ok "Suricata tece" || {
	fail "Suricata se ni zagnala"
	sed 's/^/    /' "$COMMON/out/ids.log" >&2 || true
	exit 1
}
docker exec -d "clab-$TOPO-ids" sh -c \
	'exec python3 /opt/ids/alert_forward.py >>/opt/traffic/out/forward.log 2>&1'
sleep 2

run_traffic
sleep 5
check_metrics

read -r alerts missed fronted <<<"$(python3 - "$COMMON/out" <<'PY'
import json, sys
from pathlib import Path

out = Path(sys.argv[1])
rows = [json.loads(l) for l in (out / "metrics.jsonl").read_text().splitlines() if l.strip()]
alerts = [json.loads(l) for l in (out / "alerts.jsonl").read_text().splitlines() if l.strip()]

detected = {a["sni"] for a in alerts}
expected = {r["sni"] for r in rows if r.get("category") == "phishing" and not r.get("fronting")}
hidden = {r["page"] for r in rows if r.get("fronting")}
print(len(alerts), len(expected - detected), len(hidden & detected))
PY
)"
[ "$alerts" -gt 0 ] && ok "IDS je javil $alerts zaznav" || fail "alerts.jsonl je prazen"
check "nobena nefrontana phishing domena ni zgresena" "$missed" "0"
check "frontane domene IDS ne vidi (slepa pega po zasnovi)" "$fronted" "0"
check "krmilnik je zaznave prejel" \
	"$(grep -c '"source": "alert"' "$COMMON/out/controller.jsonl")" "$alerts"
cleanup

echo
[ "$FAILURES" -eq 0 ] && echo "vse v redu" || echo "$FAILURES neuspesnih preverjanj"
exit "$FAILURES"
