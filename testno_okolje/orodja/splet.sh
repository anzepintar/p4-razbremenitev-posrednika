#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

NAME=splet
PURPOSE="Ali prestrezanje zdrzi na pravem spletu. Nabor je sto najbolj obiskanih domen
po Cloudflare Radarju. Najprej izhodisce v postavitvi C1, torej brez stikala in brez
posrednika, nato isti nabor skozi B1. Odstotek v porocilu je delez strani, ki delujejo
v B1, med tistimi, ki delujejo ze v izhodiscu; stran, ki ne dela niti brez prestrezanja,
v imenovalec ne steje."

# shellcheck source=orodja/lib.sh
. orodja/lib.sh

CSV="${CSV:-../testni_podatki/cloudflare-radar_top-100-domains_20260822.csv}"
SWEEP_CLIENTS="${SWEEP_CLIENTS:-curl chromium firefox}"
SWEEP_PROTOS="${SWEEP_PROTOS:-h2 h3}"
LIMIT="${LIMIT:-0}"
KEEP="${KEEP:-1}"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-5}"
MAX_TIME="${MAX_TIME:-20}"
PAGE_TIMEOUT="${PAGE_TIMEOUT:-30}"
RETRIES="${RETRIES:-1}"
NO_KYBER="${NO_KYBER:-0}"

export PROBE_URL="${PROBE_URL:-https://www.cloudflare.com/}"

REMOTE=/opt/traffic/out/$NAME

[ -f "$CSV" ] || {
	echo "$NAME: nabora ni v '$CSV'; podaj ga s CSV=<pot>" >&2
	exit 1
}

python3 - "$CSV" "$RESULTS/domene.json" <<'PY'
import csv, json, re, sys
from pathlib import Path

source = Path(sys.argv[1])
stamp = re.search(r"(\d{4})(\d{2})(\d{2})", source.name)
rows = list(csv.DictReader(source.open(encoding="utf-8-sig")))
domains = [
    {"rank": int(row["rank"]), "domain": row["domain"].strip().lower(),
     "categories": (row.get("categories") or "").strip()}
    for row in rows if row.get("domain")
]
Path(sys.argv[2]).write_text(json.dumps({
    "source": source.name,
    "captured": "-".join(stamp.groups()) if stamp else None,
    "domains": sorted(domains, key=lambda item: item["rank"]),
}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(f"nabor: {len(domains)} domen iz {source.name}")
PY

# Nobena domena nabora ne sme biti na laboratorijskih seznamih iz okolje/lists.
python3 - "$RESULTS/domene.json" <<'PY'
import json, sys
from pathlib import Path

sys.path.insert(0, "okolje")
import sni

domains = [item["domain"] for item in
           json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))["domains"]]
lists = sni.load("domain")
hits = sorted({
    domain for domain in domains
    for name in lists["black"] + lists["white"]
    if domain == name or (name.startswith(".") and domain.endswith(name))
})
if hits:
    print(f"OPOZORILO: {len(hits)} domen nabora je na laboratorijskih seznamih: "
          f"{', '.join(hits[:5])}")
PY

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
		--targets "$REMOTE/cilji.json" \
		--out "$REMOTE/$topo/probes_${client}_${proto}.jsonl" \
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

echo "== izhodisce C1: odjemalec - prehod, brez stikala in posrednika =="
bring_up C1

echo "  korak 0: kam apex domena pripelje"
docker exec clab-C1-client python3 -m probe --mode discover \
	--domains "$REMOTE/domene.json" --out "$REMOTE/cilji.json" \
	--limit "$LIMIT" --connect-timeout "$CONNECT_TIMEOUT" \
	--max-time "$MAX_TIME" 2>&1 | sed 's/^/    /'

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
