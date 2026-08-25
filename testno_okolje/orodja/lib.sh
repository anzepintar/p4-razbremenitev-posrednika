# Skupna strojnica meritev. Program nastavi NAME in PURPOSE, nato sourca to datoteko.

OUT=okolje/out
SUDO="${SUDO-sudo}"
TOPO_DIR=.
CURRENT=""
SETTLE="${SETTLE:-2}"
BLOCK_FAILED=0
RESULTS="$OUT/$NAME"

ARTEFACTS="metrics.jsonl summary.json proxy_flows.jsonl"
WARMUP_ARTEFACTS="metrics_ogrevanje.jsonl summary_ogrevanje.json proxy_flows.jsonl"

IFS='|' read -r PROTOCOLS MODES DOMAINS <<<"$(python3 - <<'PY'
import sys
sys.path.insert(0, "okolje")
import experiment as exp

e = exp.load()
print("|".join([
    " ".join(f"{name}:{share}" for name, share in sorted(e.protocols.items())),
    " ".join(m for m in e.modes),
    str(e.total),
]))
PY
)"

WARMUP_REQUESTS="${WARMUP_REQUESTS:-$DOMAINS}"

echo "== $NAME =="
echo "$PURPOSE" | fold -s -w 78
echo

./orodja/reclaim.sh
mkdir -p "$RESULTS"

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
	./orodja/start.sh "$topo" --lazy

	if ! docker exec "clab-$topo-client" python3 -m runner --help >/dev/null 2>&1; then
		echo "$NAME: runner v odjemalcu se ne zazene; zazeni ./orodja/build.sh" >&2
		return 1
	fi
}

probe_ok() {
	local topo="$1" domain ip code
	read -r domain ip _ <<<"$(awk '$3 == "unknown" { print; exit }' "$OUT/warmup.txt" 2>/dev/null)"
	[ -n "${domain:-}" ] || return 0
	code=$(docker exec "clab-$topo-client" curl -s -o /dev/null -w '%{http_code}' \
		--max-time 5 --cacert /opt/traffic/pki/trust.pem \
		--resolve "$domain:443:$ip" "https://$domain/index.html" 2>/dev/null || true)
	[ "$code" = "200" ]
}

ensure_alive() {
	local topo="$1"
	probe_ok "$topo" && return 0

	echo "    (podatkovna ravnina ne odgovarja, postavljam znova)" >&2
	cleanup
	if start_topo "$topo" && probe_ok "$topo"; then
		return 0
	fi
	echo "$NAME: $topo ne odgovarja niti po ponovnem postavljanju; blok prekinjam" >&2
	BLOCK_FAILED=1
	return 1
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

# Nacin "other" je ostali promet, kar je skupina unknown. Runner nacinov ne pozna.
groups_for() {
	case "$1" in
	other) echo unknown ;;
	*) echo "$1" ;;
	esac
}

warm_up() {
	local topo="$1" share="$2" groups="$3"
	client_run "$topo" "python3 -m runner --config /opt/traffic/experiment.yml \
		--quic-share $share --groups $groups --requests $WARMUP_REQUESTS \
		--workers 16 --label ogrevanje" >/dev/null 2>&1 || true
	for file in $WARMUP_ARTEFACTS; do rm -f "$OUT/$file"; done
}

# cell <postavitev> <cilj> <quic-share> ; klicatelj nastavi CELL_*
cell() {
	local topo="$1" dest="$2" share="$3"
	local groups="${CELL_GROUPS:-unknown}"
	local workers="${CELL_WORKERS:-16}"
	local duration="${CELL_DURATION:-$DURATION}"
	local warmup="${CELL_WARMUP:-$WARMUP}"
	local pace=""

	[ -n "${CELL_RATE_RPS:-}" ] && pace="--rate-rps $CELL_RATE_RPS"

	ensure_alive "$topo" || return 1

	mkdir -p "$dest"
	for file in $ARTEFACTS; do rm -f "$OUT/$file"; done
	[ "${CELL_WARMUP_PASS:-1}" = 1 ] && warm_up "$topo" "$share" "$groups"

	[ "${CELL_SWITCH:-1}" = 1 ] && collect_switch "$topo" "$dest" switch_before.json
	./orodja/nodestats.py links "$topo" "$dest/links_before.json"
	./orodja/nodestats.py cpu "$topo" "$dest/cpu_before.json"

	client_run "$topo" "python3 -m runner --config /opt/traffic/experiment.yml \
		--quic-share $share --groups $groups $pace --workers $workers \
		--duration $duration" 2>&1 | sed 's/^/    /'

	./orodja/nodestats.py cpu "$topo" "$dest/cpu_after.json"
	./orodja/nodestats.py links "$topo" "$dest/links_after.json"
	[ "${CELL_SWITCH:-1}" = 1 ] && collect_switch "$topo" "$dest" switch_after.json

	for file in $ARTEFACTS; do
		[ -f "$OUT/$file" ] && mv -f "$OUT/$file" "$dest/$file"
	done

	python3 - "$dest/meta.json" <<PY
import json, sys
json.dump({
    "meritev": "$NAME", "postavitev": "$topo", "quic_share": float("$share"),
    "groups": "$groups", "workers": int("$workers"),
    "duration_s": float("$duration"), "warmup_s": float("$warmup"),
    "rate_rps": ${CELL_RATE_RPS:-None},
}, open(sys.argv[1], "w"), indent=2, ensure_ascii=False)
PY

	[ -s "$dest/metrics.jsonl" ] || { echo "$NAME: $dest brez meritev" >&2; return 1; }
	sleep "$SETTLE"
}

finish() {
	cleanup
	./orodja/reclaim.sh
	./orodja/plot.py "$RESULTS"
}

SEARCH_START="${SEARCH_START:-8}"
SEARCH_MAX="${SEARCH_MAX:-512}"
SEARCH_TOLERANCE="${SEARCH_TOLERANCE:-5}"
TRIAL_DURATION="${TRIAL_DURATION:-12}"
TRIAL_WARMUP="${TRIAL_WARMUP:-3}"
CONFIRM_DURATION="${CONFIRM_DURATION:-30}"
CONFIRM_WARMUP="${CONFIRM_WARMUP:-5}"

workers_for() {
	python3 -c "import math,sys; print(min(256, max(16, math.ceil(float(sys.argv[1]) * 0.25))))" "$1"
}

trial() {
	local topo="$1" dest="$2" share="$3" rate="$4"
	CELL_RATE_RPS="$rate" CELL_WORKERS="$(workers_for "$rate")" \
		CELL_DURATION="$TRIAL_DURATION" CELL_WARMUP="$TRIAL_WARMUP" \
		CELL_WARMUP_PASS=0 CELL_SWITCH=0 \
		cell "$topo" "$dest/r$rate" "$share" >/dev/null 2>&1 || return 1
	./orodja/verdict.py "$dest/r$rate"
}

# search_max <postavitev> <cilj> <quic-share>
search_max() {
	local topo="$1" dest="$2" share="$3"
	local lo=0 hi=0 rate="$SEARCH_START" mid

	mkdir -p "$dest"
	warm_up "$topo" "$share" "${CELL_GROUPS:-unknown}"

	while [ "$rate" -le "$SEARCH_MAX" ]; do
		printf '    poskus %4s zahtev/s ... ' "$rate"
		if trial "$topo" "$dest" "$share" "$rate"; then
			lo="$rate"
			rate=$((rate * 2))
		else
			hi="$rate"
			break
		fi
	done

	if [ "$lo" = 0 ]; then
		echo "    $NAME: niti $SEARCH_START zahtev/s ni vzdrznih" >&2
		return 1
	fi
	[ "$hi" = 0 ] && hi=$((lo * 2))

	while [ $(((hi - lo) * 100 / hi)) -gt "$SEARCH_TOLERANCE" ]; do
		mid=$(((lo + hi) / 2))
		[ "$mid" -le "$lo" ] && break
		printf '    bisekcija %4s zahtev/s ... ' "$mid"
		if trial "$topo" "$dest" "$share" "$mid"; then
			lo="$mid"
		else
			hi="$mid"
		fi
	done

	echo "    najvecja vzdrzna hitrost: $lo zahtev/s (zgornja meja $hi)"
	python3 - "$dest/max.json" "$lo" "$hi" "$SEARCH_TOLERANCE" <<'PY'
import json, sys
lo, hi = int(sys.argv[2]), int(sys.argv[3])
json.dump({"max_rps": lo, "lo": lo, "hi": hi,
           "tolerance_pct": int(sys.argv[4]),
           "razmik_pct": round((hi - lo) / hi * 100, 1) if hi else None},
          open(sys.argv[1], "w"), indent=2, ensure_ascii=False)
PY

	echo "    potrditev pri $lo zahtev/s, ${CONFIRM_DURATION}s"
	CELL_RATE_RPS="$lo" CELL_WORKERS="$(workers_for "$lo")" \
		CELL_DURATION="$CONFIRM_DURATION" CELL_WARMUP="$CONFIRM_WARMUP" \
		cell "$topo" "$dest/potrjeno" "$share" || return 1
}

# search_all <postavitev> ; postavi topologijo in poisce mejo v obeh protokolih
search_all() {
	local topo="$1" entry proto share
	start_topo "$topo" || return 1
	BLOCK_FAILED=0
	for entry in $PROTOCOLS; do
		[ "$BLOCK_FAILED" = 1 ] && break
		proto="${entry%%:*}"
		share="${entry##*:}"
		echo "  -- $proto --"
		search_max "$topo" "$RESULTS/$topo/$proto" "$share" || true
	done
	cleanup
}

# max_rps <meritev> <postavitev> <protokol> -> hitrost ali prazno
max_rps() {
	./orodja/maxrps.py "$OUT/$1/$2/$3"
}

# Izbor nabora za pregled spleta. Tece v tekoci postavitvi in z istimi izteki kot pregled,
# zato med izborom in meritvijo ni razlike ne v okolju ne v casu ne v merilu. Prvi korak
# poisce koncnega gostitelja apex domene, drugi pri vsakem dosegljivem preveri oba protokola.
#
# select_nabor <postavitev> <oddaljeni imenik>
select_nabor() {
	local topo="$1" remote="$2"
	local csv="${CSV:-../testni_podatki/cloudflare-radar_top-1000-domains_20260701-20260731.csv}"
	local nabor="${NABOR:-okolje/splet_nabor.json}"
	local limit="${SELECT_LIMIT:-0}" jobs="${SELECT_JOBS:-64}" retries="${RETRIES:-1}"
	local connect="${CONNECT_TIMEOUT:-10}" maxtime="${MAX_TIME:-10}"

	[ -f "$csv" ] || {
		echo "$NAME: izvoza ni v '$csv'; podaj ga s CSV=<pot>" >&2
		return 1
	}

	python3 - "$csv" "$RESULTS/domene.json" <<'PY'
import csv, json, re, sys
from pathlib import Path

source = Path(sys.argv[1])
stamps = re.findall(r"\d{8}", source.name)
seen, domains = set(), []
for row in csv.DictReader(source.open(encoding="utf-8-sig")):
    domain = (row.get("domain") or "").strip().lower()
    if domain and domain not in seen:
        seen.add(domain)
        domains.append({"domain": domain})

Path(sys.argv[2]).write_text(json.dumps({
    "source": source.name,
    "captured": "/".join(f"{s[:4]}-{s[4:6]}-{s[6:]}" for s in stamps) or None,
    "domains": sorted(domains, key=lambda item: item["domain"]),
}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(f"    izvoz: {len(domains)} domen iz {source.name}")
PY

	docker exec "clab-$topo-client" python3 -m probe --mode select \
		--domains "$remote/domene.json" \
		--out "$remote/nabor.json" \
		--apex-out "$remote/apex.json" \
		--limit "$limit" --jobs "$jobs" --retries "$retries" \
		--connect-timeout "$connect" --max-time "$maxtime" 2>&1 | sed 's/^/    /'

	cp -f "$RESULTS/nabor.json" "$nabor"

	python3 - "$nabor" "$RESULTS/apex.json" <<'PY'
import json, sys
from pathlib import Path

stats = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))["stats"]
print(f"    izvoz {stats['domains']} domen, dosegljivih {stats['reachable']}, "
      f"HTTP/2 {stats['h2']}, HTTP/3 {stats['h3']}, oba {stats['both']}, "
      f"samo HTTP/2 {stats['h2_only']}, samo HTTP/3 {stats['h3_only']}")
print(f"    nabor: {stats['selected']} domen v {sys.argv[1]}")
print(f"    prvi korak z razlogi osipa: {sys.argv[2]}")
PY
}

# Nobena domena nabora ne sme biti na laboratorijskih seznamih iz okolje/lists.
check_lists() {
	python3 - "$RESULTS/nabor.json" <<'PY'
import json, sys
from pathlib import Path

sys.path.insert(0, "okolje")
import sni

domains = [item["domain"] for item in
           json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))["targets"]]
lists = sni.load("domain")
hits = sorted({
    domain for domain in domains
    for name in lists["black"] + lists["white"]
    if domain == name or (name.startswith(".") and domain.endswith(name))
})
if hits:
    print(f"    OPOZORILO: {len(hits)} domen nabora je na laboratorijskih seznamih: "
          f"{', '.join(hits[:5])}")
PY
}

# Obremenitev je stalna in v obeh postavitvah enaka. Vrednosti sta izpeljani iz maksimumov,
# ki ju je nasel m2, in izbrani pod manjsim od njiju.
RATE_H2="${RATE_H2:-80}"
RATE_H3="${RATE_H3:-10}"

load_rate() {
	local proto="$1" a b lower picked
	case "$proto" in
	h3) picked="$RATE_H3" ;;
	*) picked="$RATE_H2" ;;
	esac
	a="$(max_rps m2_stikalo A0 "$proto")"
	b="$(max_rps m2_stikalo B0 "$proto")"
	if [ -n "$a" ] && [ -n "$b" ]; then
		lower=$((a < b ? a : b))
		[ "$picked" -ge "$lower" ] &&
			echo "    opozorilo: $picked zahtev/s ni pod maksimumom m2 ($a in $b)" >&2
	fi
	echo "$picked"
}
