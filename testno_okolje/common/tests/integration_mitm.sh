#!/usr/bin/env bash
set -euo pipefail

COMMON="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
SERVER=traffic-itm-server
PROXY=traffic-itm-proxy
FAILURES=0

cleanup() {
	docker run --rm -v "$WORK:/w" server:latest sh -c 'rm -rf /w/* /w/.[!.]*' >/dev/null 2>&1 || true
	docker rm -f "$SERVER" "$PROXY" >/dev/null 2>&1 || true
	rm -rf "$WORK"
}
trap cleanup EXIT

ok() { printf '  \033[32mok\033[0m   %s\n' "$1"; }
fail() {
	printf '  \033[31mFAIL\033[0m %s\n' "$1"
	FAILURES=$((FAILURES + 1))
}
check() { [ "$2" = "$3" ] && ok "$1" || fail "$1: pricakovano '$3', dobljeno '$2'"; }

client() { docker run --rm --network host -v "$COMMON:/opt/traffic:ro" -v "$WORK:/work" client:latest "$@"; }

echo "== transportni protokol reverse specifikacije =="
transport=$(docker run --rm proxy:latest python3 -c \
	"from mitmproxy.proxy.mode_specs import ProxyMode; print(ProxyMode.parse('reverse:https://127.0.0.2:443@443').transport_protocol)")
check "reverse:https posluša na obeh transportih" "$transport" "both"

echo
[ -d "$COMMON/server/testset/osnovni" ] || {
	echo "nabora ni - pozeni ./build_testset.py" >&2
	exit 1
}

read -r LEGIT1 LEGIT2 LEGIT3 PHISH <<<"$(python3 - "$COMMON/server/testset/osnovni/sites.json" <<'PYX'
import json, sys
sites = json.load(open(sys.argv[1]))
ben = sorted(s["domain"] for s in sites if s["label"] == "ben")
mal = sorted(s["domain"] for s in sites if s["label"] == "mal")
print(ben[0], ben[1], ben[2], mal[0])
PYX
)"

echo "== zagon streznika na 127.0.0.2 =="
mkdir -p "$WORK/out"
sed 's/^\( *ips:\) \[127\.0\.0\.1\]/\1 [127.0.0.2]/' \
	"$COMMON/tests/scenario.local.yml" >"$WORK/scenario.origin.yml"
python3 "$COMMON/gen_caddyfile.py" --config "$WORK/scenario.origin.yml" \
	--testset "$COMMON/server/testset" --access-log /data/out/caddy-access.json \
	-o "$WORK/sites.caddy" >/dev/null
docker run -d --name "$SERVER" --network host \
	-e SITES=/data/sites.caddy \
	-v "$COMMON:/opt/traffic:ro" -v "$WORK:/data" server:latest \
	caddy run --config /etc/caddy/Caddyfile >/dev/null

CA=/data/caddy/pki/authorities/local/root.crt
for _ in $(seq 1 60); do
	docker exec "$SERVER" test -s "$CA" 2>/dev/null && break
	sleep 1
done
docker exec "$SERVER" test -s "$CA" 2>/dev/null || {
	docker logs "$SERVER" >&2
	exit 1
}
docker exec "$SERVER" cat "$CA" >"$WORK/trust.pem"
chmod 644 "$WORK/trust.pem"
ok "Caddy tece"

echo
echo "== zagon mitmproxy v reverse nacinu na 127.0.0.1 =="
docker run -d --name "$PROXY" --network host -v "$WORK:/work" proxy:latest \
	mitmdump --set confdir=/work/mitmconf \
	--set ssl_verify_upstream_trusted_ca=/work/trust.pem \
	--set keep_host_header=true \
	--set flow_detail=2 \
	-s /opt/proxy/sni_passthrough.py \
	--mode "reverse:https://127.0.0.2:443@127.0.0.1:443" >/dev/null

MITM_CA="$WORK/mitmconf/mitmproxy-ca-cert.pem"
for _ in $(seq 1 60); do
	[ -s "$MITM_CA" ] && break
	sleep 1
done
[ -s "$MITM_CA" ] || {
	docker logs "$PROXY" >&2
	exit 1
}
cat "$MITM_CA" >>"$WORK/trust.pem"
sleep 2
ok "mitmproxy tece, oba CA sta v trust.pem"

CURL="curl --silent --show-error --cacert /work/trust.pem"

echo
echo "== prestrezanje =="
check "HTTP/2 gre skozi mitm" \
	"$(client $CURL --http2 --resolve $LEGIT1:443:127.0.0.1 \
		-o /dev/null -w '%{http_code}|%{http_version}' https://$LEGIT1/index.html)" \
	"200|2"

check "HTTP/3 gre skozi mitm" \
	"$(client $CURL --http3-only --resolve $LEGIT1:443:127.0.0.1 \
		-o /dev/null -w '%{http_code}|%{http_version}' https://$LEGIT1/index.html)" \
	"200|3"

echo
echo "== deljeni naslov prezivi reverse nacin =="
for domain in "$LEGIT1" "$LEGIT2" "$LEGIT3" "$PHISH"; do
	seen=$(client $CURL --http3-only --resolve "$domain:443:127.0.0.1" \
		-o /dev/null -w '%header{x-sni}|%header{x-domain}' "https://$domain/index.html")
	check "$domain pride do svojega bloka" "$seen" "$domain|$domain"
done

echo
echo "== mitmproxy je promet res razstavil =="
logs=$(docker logs "$PROXY" 2>&1)
# URL v izpisu kaze naslov izvora, zato domeno iscemo v glavi odgovora.
grep -q "HTTP/3" <<<"$logs" && ok "posrednik je razstavil zahtevo HTTP/3" ||
	fail "v dnevniku posrednika ni zahteve HTTP/3"
grep -q "x-sni: $LEGIT1" <<<"$logs" && ok "odgovor izvora pripada pravemu bloku" ||
	fail "posrednik ni videl odgovora pravega bloka"

echo
[ "$FAILURES" -eq 0 ] && {
	echo "vse v redu"
	echo "opomba: uspesen H3 skozi mitm hkrati potrjuje QUIC v1 - mitmproxy druge razlicice ne podpira."
} || echo "$FAILURES neuspesnih preverjanj"
exit "$FAILURES"
