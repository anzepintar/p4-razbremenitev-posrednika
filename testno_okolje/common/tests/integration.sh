#!/usr/bin/env bash
set -euo pipefail

COMMON="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
SERVER=traffic-it-server
FAILURES=0

cleanup() {
	docker run --rm -v "$WORK:/w" server:latest sh -c 'rm -rf /w/* /w/.[!.]*' >/dev/null 2>&1 || true
	docker rm -f "$SERVER" >/dev/null 2>&1 || true
	rm -rf "$WORK"
}
trap cleanup EXIT

ok() { printf '  \033[32mok\033[0m   %s\n' "$1"; }
fail() {
	printf '  \033[31mFAIL\033[0m %s\n' "$1"
	FAILURES=$((FAILURES + 1))
}
check() { [ "$2" = "$3" ] && ok "$1" || fail "$1: pricakovano '$3', dobljeno '$2'"; }

client() { docker run --rm --network host -v "$COMMON:/opt/traffic:ro" -v "$WORK:/work" "$@"; }

[ -d "$COMMON/server/testset/osnovni" ] || {
	echo "nabora ni - pozeni ./build_testset.py" >&2
	exit 1
}

read -r LEGIT1 LEGIT2 LEGIT3 PHISH <<<"$(python3 - "$COMMON/server/testset/osnovni/sites.json" <<'PY'
import json, sys
sites = json.load(open(sys.argv[1]))
ben = sorted(s["domain"] for s in sites if s["label"] == "ben")
mal = sorted(s["domain"] for s in sites if s["label"] == "mal")
print(ben[0], ben[1], ben[2], mal[0])
PY
)"

echo "== priprava =="
mkdir -p "$WORK/out"
python3 "$COMMON/gen_caddyfile.py" --config "$COMMON/tests/scenario.local.yml" \
	--testset "$COMMON/server/testset" --access-log /data/out/caddy-access.json \
	-o "$WORK/sites.caddy" >/dev/null
ok "sites.caddy za loopback ($LEGIT1, $PHISH, ...)"

echo
echo "== zagon streznika =="
docker run -d --name "$SERVER" --network host \
	-e SITES=/data/sites.caddy \
	-v "$COMMON:/opt/traffic:ro" -v "$WORK:/data" server:latest \
	caddy run --config /etc/caddy/Caddyfile >/dev/null

CA=/data/caddy/pki/authorities/local/root.crt
for _ in $(seq 1 60); do
	docker exec "$SERVER" test -s "$CA" 2>/dev/null && break
	sleep 1
done
if ! docker exec "$SERVER" test -s "$CA" 2>/dev/null; then
	echo "CA se ni pojavil; dnevnik streznika:" >&2
	docker logs "$SERVER" >&2 || true
	exit 1
fi
docker exec "$SERVER" cat "$CA" >"$WORK/trust.pem"
chmod 644 "$WORK/trust.pem"
ok "Caddy tece, lokalni CA je na voljo"

CURL="curl --silent --show-error --cacert /work/trust.pem"

echo
echo "== protokola =="
check "HTTP/2 se pogodi" \
	"$(client client:latest $CURL --http2 --resolve "$LEGIT1:443:127.0.0.1" \
		-o /dev/null -w '%{http_code}|%{http_version}' "https://$LEGIT1/index.html")" "200|2"

check "HTTP/3 se pogodi" \
	"$(client client:latest $CURL --http3-only --resolve "$LEGIT1:443:127.0.0.1" \
		-o /dev/null -w '%{http_code}|%{http_version}' "https://$LEGIT1/index.html")" "200|3"

echo
echo "== SNI usmerjanje na deljenem naslovu =="
for domain in "$LEGIT1" "$LEGIT2" "$LEGIT3" "$PHISH"; do
	seen=$(client client:latest $CURL --http3-only --resolve "$domain:443:127.0.0.1" \
		-o /dev/null -w '%header{x-sni}|%header{x-domain}' "https://$domain/index.html")
	check "streznik vidi pravi SNI za $domain" "$seen" "$domain|$domain"
done

echo
echo "== vsebina iz nabora =="
body=$(client client:latest $CURL --http3-only --resolve "$PHISH:443:127.0.0.1" \
	"https://$PHISH/index.html" | md5sum | cut -d' ' -f1)
want=$(md5sum "$COMMON/server/testset/osnovni/$PHISH/index.html" | cut -d' ' -f1)
check "telo je bajt za bajt enaka stran iz nabora" "$body" "$want"

check "nepostrezen podvir vrne 404" \
	"$(client client:latest $CURL --http2 --resolve "$LEGIT1:443:127.0.0.1" \
		-o /dev/null -w '%{http_code}' "https://$LEGIT1/ni-me.css")" "404"

echo
echo "== domain fronting =="
fronted=$(client client:latest $CURL --http2 --resolve "$LEGIT1:443:127.0.0.1" \
	--header "Host: $PHISH" -o /dev/null \
	-w '%header{x-sni}|%header{x-domain}' "https://$LEGIT1/index.html")
check "SNI in :authority se razlikujeta" "$fronted" "$LEGIT1|$PHISH"

echo
echo "== SSLKEYLOGFILE =="
client -e SSLKEYLOGFILE=/work/keys.log client:latest sh -c \
	"$CURL --http2 --resolve $LEGIT1:443:127.0.0.1 -o /dev/null https://$LEGIT1/index.html"
h2_lines=$(wc -l <"$WORK/keys.log")
client -e SSLKEYLOGFILE=/work/keys.log client:latest sh -c \
	"$CURL --http3-only --resolve $LEGIT1:443:127.0.0.1 -o /dev/null https://$LEGIT1/index.html"
h3_lines=$(wc -l <"$WORK/keys.log")
[ "$h2_lines" -gt 0 ] && ok "TLS kljuci zapisani ($h2_lines vrstic)" || fail "TLS kljuci manjkajo"
[ "$h3_lines" -gt "$h2_lines" ] && ok "QUIC kljuci dodani ($h3_lines vrstic)" ||
	fail "QUIC kljuci niso bili dodani ($h2_lines -> $h3_lines)"

echo
echo "== orkestrator od konca do konca =="
client -e SSLKEYLOGFILE=/work/keys.log client:latest \
	python3 -m runner --config /opt/traffic/tests/scenario.local.yml --requests 4 >/dev/null

python3 - "$WORK/out/metrics.jsonl" "$WORK/out/summary.json" <<'PY' && ok "meritve so smiselne" || fail "meritve niso smiselne"
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
summary = json.load(open(sys.argv[2]))
assert rows, "ni meritev"

pages = [r for r in rows if str(r["url"]).endswith("/index.html")]
assert pages, "ni zahtev za strani"
assert all(r["http_code"] == 200 for r in pages), "neka stran ni bila postrezena"
assert {r["http_version"] for r in pages} == {"2", "3"}, "manjka eden od protokolov"

assert {r["local_ip"] for r in rows} == {"127.0.0.1", "127.0.0.2", "127.0.0.3"}, "izvorni IP-ji se ne locijo"

fronted = [r for r in rows if r["fronting"]]
assert fronted, "fronting ni bil izveden"
assert all(r["sni"] != r["authority"] for r in fronted), "fronting brez neujemanja"
assert all(r["server_domain"] == r["authority"] for r in fronted), "streznik ni sledil :authority"

assert {r["category"] for r in rows if r["category"]} <= {"legit", "phishing"}
assert summary["total"]["requests"] == len(rows)
PY

echo
[ "$FAILURES" -eq 0 ] && echo "vse v redu" || echo "$FAILURES neuspesnih preverjanj"
exit "$FAILURES"
