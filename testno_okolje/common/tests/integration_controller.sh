#!/usr/bin/env bash
set -euo pipefail

COMMON="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOPO_DIR="$(cd "$COMMON/.." && pwd)"
TOPO=mitm_controller
SUDO="${SUDO-sudo}"
REQUESTS="${1:-3}"
FAILURES=0

cleanup() { $SUDO clab destroy -t "$TOPO_DIR/$TOPO.clab.yml" --cleanup >/dev/null 2>&1 || true; }
trap cleanup EXIT

ok() { printf '  \033[32mok\033[0m   %s\n' "$1"; }
fail() {
	printf '  \033[31mFAIL\033[0m %s\n' "$1"
	FAILURES=$((FAILURES + 1))
}
check() { [ "$2" = "$3" ] && ok "$1" || fail "$1: pricakovano '$3', dobljeno '$2'"; }

wait_for() {
	local node="$1" port="$2"
	for _ in $(seq 1 30); do
		docker exec "clab-$TOPO-$node" ss -lntu 2>/dev/null | grep -q ":$port" && return 0
		sleep 1
	done
	return 1
}

echo "== postavitev $TOPO =="
$SUDO clab deploy -t "$TOPO_DIR/$TOPO.clab.yml" --reconfigure >/dev/null
ok "topologija stoji"

mkdir -p "$COMMON/out"
rm -f "$COMMON/out/bypass.jsonl" "$COMMON/out/mitm.log"

docker exec -d "clab-$TOPO-controller" sh -c \
	'exec python3 /opt/traffic/controller/controller.py --policy mitm \
	 >>/opt/traffic/out/controller.log 2>&1'
wait_for controller 8080 && ok "krmilnik posluša na 8080" || {
	fail "krmilnik se ni zagnal"
	exit 1
}

decide=$(docker exec "clab-$TOPO-controller" python3 -c '
import json, urllib.request
for ip in ("10.0.1.10", "10.0.1.12", "10.9.9.9"):
    with urllib.request.urlopen(f"http://10.20.3.1:8080/decide?src={ip}", timeout=3) as r:
        print(json.load(r)["action"], end=" ")
')
check "krmilnik odloca po zaupanju, neznan naslov pregleda" "$decide" "direct inspect inspect "

echo
echo "== posrednik z addonom =="
clab exec -t "$TOPO_DIR/$TOPO.clab.yml" --label clab-node-name=server \
	--cmd "caddy start --config /opt/traffic/server/Caddyfile" >/dev/null 2>&1
"$COMMON/trust.sh" "$TOPO" >/dev/null

docker exec -d "clab-$TOPO-mitm" sh -c 'exec mitmdump "$@" >>/opt/traffic/out/mitm.log 2>&1' _ \
	--set confdir=/data/mitmproxy \
	--set ssl_verify_upstream_trusted_ca=/opt/traffic/pki/trust.pem \
	--set keep_host_header=true \
	-s /opt/proxy/sni_passthrough.py \
	-s /opt/proxy/controller_bypass.py \
	--mode reverse:https://10.0.2.10:443@8443 \
	--mode reverse:https://10.0.2.11:443@8444 \
	--mode reverse:https://10.0.2.12:443@8445
for _ in $(seq 1 60); do
	docker exec "clab-$TOPO-mitm" test -s /data/mitmproxy/mitmproxy-ca-cert.pem 2>/dev/null && break
	sleep 1
done
"$COMMON/trust.sh" "$TOPO" >/dev/null
wait_for mitm 8443 && ok "posrednik posluša" || fail "posrednik se ni zagnal"

rm -f "$COMMON/out/metrics.jsonl" "$COMMON/out/summary.json"
clab exec -t "$TOPO_DIR/$TOPO.clab.yml" --label clab-node-name=client \
	--cmd "python3 -m runner --config /opt/traffic/scenario.yml --requests $REQUESTS" >/dev/null 2>&1

echo
echo "== odlocitve =="
read -r rows errors bypassed inspected quic <<<"$(python3 - "$COMMON/out" <<'PY'
import json, sys
from pathlib import Path

out = Path(sys.argv[1])
metrics = [json.loads(l) for l in (out / "metrics.jsonl").read_text().splitlines() if l.strip()]
decisions = [json.loads(l) for l in (out / "bypass.jsonl").read_text().splitlines() if l.strip()]

errors = sum(1 for r in metrics if r.get("exitcode") != 0)
bypassed = {r["src"] for r in decisions if r["action"] == "direct"}
inspected = {r["src"] for r in decisions if r["action"] == "inspect" and not r["forced"]}
quic = sum(1 for r in decisions if r["forced"] == "quic")
print(len(metrics), errors, ",".join(sorted(bypassed)), ",".join(sorted(inspected)), quic)
PY
)"

[ "$rows" -gt 0 ] && ok "runner je zapisal $rows vrstic" || fail "metrics.jsonl je prazen"
check "vse zahteve so uspele" "$errors" "0"
check "visoko in srednje zaupanje gresta mimo posrednika" "$bypassed" "10.0.1.10,10.0.1.11"
check "nizko zaupanje je pregledano" "$inspected" "10.0.1.12"
[ "$quic" -gt 0 ] && ok "QUIC je vsiljeno pregledan ($quic sej), obid pri h3 ni mogoc" ||
	fail "v bypass.jsonl ni nobene seje s forced=quic"

echo
[ "$FAILURES" -eq 0 ] && echo "vse v redu" || echo "$FAILURES neuspesnih preverjanj"
exit "$FAILURES"
